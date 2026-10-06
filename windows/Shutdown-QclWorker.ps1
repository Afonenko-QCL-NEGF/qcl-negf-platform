param(
    [Parameter(Mandatory)][string] $Controller,
    [Parameter(Mandatory)][string] $Node,
    [string] $SshKey,
    [string] $SshExecutable = 'ssh',
    [double] $PollSeconds = 5
)

$ErrorActionPreference = 'Stop'
if ($Controller -notmatch '^(?:[a-z_][a-z0-9_-]*@)?[a-zA-Z0-9][a-zA-Z0-9.-]*$' -or
    $Node -notmatch '^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$' -or $PollSeconds -le 0) {
    throw 'Use a trusted controller SSH target, valid Slurm node and positive poll interval.'
}

$sshArguments = @('-o', 'BatchMode=yes', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3')
if ($SshKey) { $sshArguments += @('-i', $SshKey) }
$sshArguments += @($Controller, "sudo -n qcl-negf-worker-lifecycle shutdown --node $Node")

# GPO is a candidate only: Hyper-V guest, VMMS and network must survive until
# this controller-side verifier has proved every captured attempt durable AND
# terminated. There is deliberately no total shutdown timeout.
while ($true) {
    try {
        $response = & $SshExecutable @sshArguments
        if ($LASTEXITCODE -eq 0) {
            $proof = ($response -join "`n") | ConvertFrom-Json
            if ($proof.node -eq $Node -and $proof.safe_to_shutdown -eq $true) {
                Write-Output ($proof | ConvertTo-Json -Compress)
                break
            }
            Write-Warning 'Controller returned no complete scoped shutdown proof; waiting.'
        } else {
            Write-Warning "Controller verification failed (SSH exit $LASTEXITCODE); waiting."
        }
    } catch {
        Write-Warning "Shutdown remains waiting: $($_.Exception.Message)"
    }
    Start-Sleep -Milliseconds ([int]($PollSeconds * 1000))
}
