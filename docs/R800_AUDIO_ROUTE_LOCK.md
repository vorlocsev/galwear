# R800 Audio route transaction lock (NON-RELEASE)

Base bcf7a59edf751c50bbbe649278a9c5a45bf57f35, all six workflows passed.
Per-device route_lock serializes the entire media route/PCM open,
standby and rollback transactions across input and output. HFP takes
device, output, input then route lock, after media standby; unlock
route before HFP rollback reacquires stream locks. Steady-state PCM
read/write does not take route_lock. Device mutex initialization
errors are handled and route lock destroyed at close.
Host fault injection verifies lock release on success/failure.
Static checks cover lock hierarchy and scope.

Not a guarantee against blocking driver calls, multi-device instances,
partial hardware rollback, or framework callbacks concurrent with close.
Audio device close still requires framework to quiesce/close streams.
DSP and physical HFP untested. safe_to_flash=false.
