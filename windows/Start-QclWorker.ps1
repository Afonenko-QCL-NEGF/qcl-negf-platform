param(
    [Parameter(Mandatory)][string] $Controller,
    [Parameter(Mandatory)][string] $Node,
    [Parameter(Mandatory)][string] $WorkerTarget,
    [Parameter(Mandatory)][string] $VmName,
    [string] $SshKey,
    [double] $PollSeconds = 5
)

$ErrorActionPreference = 'Stop'
$targetPattern = '^(?:[a-z_][a-z0-9_-]*@)?[a-zA-Z0-9][a-zA-Z0-9.-]*$'
if ($Controller -notmatch $targetPattern -or $WorkerTarget -notmatch $targetPattern -or
    $Node -notmatch '^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$' -or $PollSeconds -le 0) {
    throw 'Use trusted SSH targets, a valid Slurm node and positive poll interval.'
}

# The same CPU-only Linux worker image and role are used on both Windows hosts.
# An unavailable Hyper-V/nested virtualization capability is a hardware blocker.
$vm = Get-VM -Name $VmName
if ($vm.State -ne 'Running') { Start-VM -Name $VmName }

$sshArguments = @('-o', 'BatchMode=yes', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3')
if ($SshKey) { $sshArguments += @('-i', $SshKey) }
$sshArguments += @($Controller, "sudo -n qcl-negf-worker-lifecycle startup --node $Node --target $WorkerTarget")
while ($true) {
    & ssh @sshArguments
    if ($LASTEXITCODE -eq 0) { break }
    Write-Warning 'Worker remains drained until application delivery and verification succeed.'
    Start-Sleep -Milliseconds ([int]($PollSeconds * 1000))
}
