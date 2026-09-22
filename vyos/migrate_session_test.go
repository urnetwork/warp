package vyos

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Execute the rendered script with only the device template replaced. The
// template records commands after configure; no device or network is involved.
func runSyntheticMigrationSession(t *testing.T, configureStatus int, sourceStatus int) (string, error) {
	t.Helper()
	directory := t.TempDir()
	recordPath := filepath.Join(directory, "commands")
	templatePath := filepath.Join(directory, "synthetic-template")
	template := fmt.Sprintf(`configure() { printf 'configure\n' >> %s; return %d; }
set() { printf 'set\n' >> %s; }
delete() { printf 'delete\n' >> %s; }
commit() { printf 'commit\n' >> %s; }
configure_exit() { printf 'cleanup\n' >> %s; }
vyatta_exit_configure() { printf ':\n'; }
return %d
`, ShellQuote(recordPath), configureStatus, ShellQuote(recordPath), ShellQuote(recordPath), ShellQuote(recordPath), ShellQuote(recordPath), sourceStatus)
	if err := os.WriteFile(templatePath, []byte(template), 0600); err != nil {
		t.Fatal(err)
	}
	migration := &Migration{Sets: []Command{{Op: "set", Path: []string{"system", "description", "synthetic-change"}}}}
	script := migration.Script(ScriptOptions{Router: "synthetic-router", Env: "synthetic"})
	const templateCommand = "source /opt/vyatta/etc/functions/script-template"
	if strings.Count(script, templateCommand) != 1 {
		t.Fatal("rendered script did not have one device template boundary")
	}
	script = strings.Replace(script, templateCommand, "source "+ShellQuote(templatePath), 1)
	scriptPath := filepath.Join(directory, "migration.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := exec.CommandContext(ctx, "bash", scriptPath).Run()
	if ctx.Err() != nil {
		t.Fatal("bounded synthetic script execution did not terminate")
	}
	commands, readErr := os.ReadFile(recordPath)
	if readErr != nil && !os.IsNotExist(readErr) {
		t.Fatal(readErr)
	}
	return string(commands), err
}

func TestMigrationScriptAbortsWhenConfigureFails(t *testing.T) {
	commands, err := runSyntheticMigrationSession(t, 1, 0)
	if err == nil {
		t.Error("failed configure was reported successful")
	}
	if commands != "configure\n" {
		t.Error("failed configure continued into mutation, commit or cleanup")
	}
}

func TestMigrationScriptEntersSessionBeforeMutation(t *testing.T) {
	commands, err := runSyntheticMigrationSession(t, 0, 0)
	if err != nil || commands != "configure\nset\ncommit\ncleanup\n" {
		t.Fatal("successful synthetic session did not exercise mutation, commit and cleanup")
	}
}

func TestMigrationScriptAbortsWhenTemplateSourceFails(t *testing.T) {
	// All commands were already defined when the synthetic template failed.
	// A source failure must still stop before entering its partial session.
	commands, err := runSyntheticMigrationSession(t, 0, 1)
	if err == nil {
		t.Error("failed template source was reported successful")
	}
	if commands != "" {
		t.Error("failed template source continued into configure or mutation")
	}
}
