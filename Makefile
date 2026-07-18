
all: local_routing_on

# note for mobile dev, you will need to also add DNS entries for the env aliases
# (e.g. <host>-<service>.<domain>)
# to be the IP of this host on the LAN shared with the mobile devices
local_routing_on:
	sudo hostctl add domains warp_local $$(warpctl lb hosts local --envalias=$$(hostname) | awk '{ print "\""$$0"\""}')

local_routing_off:
	sudo hostctl remove warp_local
