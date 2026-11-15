// Ask the installed fw4 model for its topology, without enabling native offload.
const fw4 = require("fw4");
fw4.load();
fw4.state.defaults.flow_offloading = true;
fw4.state.defaults.flow_offloading_hw = false;
print(join(",", fw4.resolve_offload_devices()), "\n");
