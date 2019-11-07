param
(
    [Parameter(Mandatory=$true)]
    [string] $NetworkControllerName,

    [Parameter(Mandatory=$false)]
    [PSCredential] $Credential,

    [Parameter(Mandatory=$false)]
    [string] $XMLReportFileName = 'NetworkControllerValidationReport',

    [Parameter(Mandatory=$false)]
    [string] $HTMLReportFileName = 'NetworkControllerValidationReport'
)


function ExecuteSDNValidationTests
{
    #c:\SDN Validation Tool = Split-Path -Path:$PSCommandPath -Parent

    $ncServersUri = "https://$NetworkControllerName/networking/v1/servers"

    $logDate = "$(Get-Date -Format "yyyy.MM.dd_hh.mm.ss")"
    $XmlReportPath = "c:\SDN Validation Tool\XMLReportFileName$logDate.xml"
    $FullHtmlReportPath = "c:\SDN Validation Tool\SDN_Validation_Report_$logDate.htm"
    $health = 'Healthy'
    $Report = 'Validation Test Report'

    # Add a binding redirect and try again. Parts of the Dev15 preview SDK have a
    # dependency on the 6.0.0.0 Newtonsoft.Json DLL, while other parts reference
    # the 10.0.0.0 Newtonsoft.Json DLL.
    LogEvent "Adding assembly resolver."

    
    $source =  
@'
        using System;
        using System.Linq;
        using System.Reflection;
        using System.Text.RegularExpressions;
        using System.IO;
         
        public class Redirector
        {
            public readonly ResolveEventHandler EventHandler;
            public string resolvePath { get; private set; }
            
            public Redirector(string executionPath)
            {
                resolvePath = executionPath;
                this.EventHandler = new ResolveEventHandler(AssemblyResolve);
            }
            
            public Assembly AssemblyResolve(object sender, ResolveEventArgs resolveEventArgs)
            {
                //Console.WriteLine("OnAssemblyResolve: {0}", resolveEventArgs.Name);
                if(resolveEventArgs.Name.Contains("System.Net.Http.Formatting"))
                {
                    //Console.WriteLine("Attempting {0} success", resolveEventArgs.Name);
                    string path = Path.Combine(resolvePath, "System.Net.Http.Formatting.dll"); 
                    Assembly redirected = System.Reflection.Assembly.LoadFrom(path);
                    //Console.WriteLine("Redirecting {0} success", resolveEventArgs.Name);
                    return redirected;
                }
                else if(resolveEventArgs.Name.Contains("Newtonsoft.Json"))
                {
                    //Console.WriteLine("Attempting {0} success", resolveEventArgs.Name);
                    string path = Path.Combine(resolvePath, "Newtonsoft.Json.dll"); 
                    Assembly redirected = System.Reflection.Assembly.LoadFrom(path);
                    //Console.WriteLine("Redirecting {0} success", resolveEventArgs.Name);
                    return redirected;
                }
                return null;
            }
        }
'@

    $type = Add-Type -TypeDefinition $source -PassThru 
    $redirectClass = [Redirector]::new("c:\SDN Validation Tool")
    
    [System.AppDomain]::CurrentDomain.add_AssemblyResolve($redirectClass.EventHandler)
    
    [System.Reflection.Assembly]::LoadFrom("c:\SDN Validation Tool\Microsoft.NetworkController.Validation.dll")
    [System.Reflection.Assembly]::LoadFrom("c:\SDN Validation Tool\Microsoft.NetworkController.Validation.Common.dll")

    LogEvent "Saving current TrustedHosts"
    $savedTrustedHosts = GetTrustedHosts
    #Load the validation module and run tests
    try
    {
        SetTrustedHostsToAll

        $DefaultCreds = New-Object Microsoft.NetworkController.Validation.Common.NCValidationCredential
        $DefaultCreds.CredentialType = [Microsoft.NetworkController.Validation.Common.NCValidationCredentialType]::UserNamePassword

        if ($null -eq $Credential)
        {
            LogEvent "No credentials provided"
        }
        else
        {
            if ($null -eq $Credential.UserName)
            {
                $DefaultCreds.UserName = "localadminuser"
            }
            else
            {
                $DefaultCreds.UserName = $Credential.UserName
            }

            if ($null -eq $Credential.Password)
            {
                LogEvent "No password provided"
            }
            else
            {
                $DefaultCreds.Password = $Credential.Password
            }
        }

        LogEvent "Creating an instance of Validation Engine"
        $ValidationEngine = [Microsoft.NetworkController.Validation.NCValidationEngine]::CreateValidationEngine()

        $ValidationEngine.NetworkControllerCredential = $DefaultCreds
        $ValidationEngine.HostCredential = $DefaultCreds
        $ValidationEngine.RestEndPoint = $NetworkControllerName

        #Try to get all Network Controller managed hosts and pass to Validation Engine
        LogEvent "Getting all Network Controller managed hosts' IPs"
        $nodes = GetAllHostManagementAddresses $ncServersUri
        foreach ($node in $nodes.Keys)
        {
            $ValidationEngine.AddNode($node, $DefaultCreds)
        }

        #Now Load and run tests
        LogEvent "Loading tests"
        $ValidationEngine.LoadTests()

        LogEvent "Executing the Validation Tests on the Validation Engine."
        $Result = $ValidationEngine.ExecuteTests($XmlReportPath)

        $health = 'Healthy'
        if (($Result.OverallResult -band [Microsoft.NetworkController.Validation.Common.NCValidationResultBitValues]::HadFailures) -ne 0)
        {
            $health = 'Failed'
        }
        elseif (($Result.OverallResult -band [Microsoft.NetworkController.Validation.Common.NCValidationResultBitValues]::HadWarnings) -ne 0)
        {
            $health = 'Warning'
        }

        $Report = $Result.OverallDescription

        [Microsoft.NetworkController.Validation.Common.XmlReportRenderer]::TransformStandardHtmlReport($XmlReportPath, $FullHtmlReportPath)
        LogEvent "Removing temporary file $XmlReportPath"
        #Remove-Item -Path $XmlReportPath

        LogEvent "Check full report ($FullHtmlReportPath)"

    }
    catch
    {
        $health = 'Failed'
        $Report = 'Validation Tests execution failed. Exception: ' + $_
        LogEvent "Failed while running validation tests"
    }
    finally
    {
        LogEvent "Restoring saved TrustedHosts"
        SetTrustedHosts $savedTrustedHosts
    }
    $ExecutionResult = 'Overall Health: ' + $health + '. Report: ' + $Report

    return [PSCustomObject] @{
        Health = $health
        ExecutionResult = $ExecutionResult
    }
}


function SetTrustedHosts
{
    param ($value)
    Set-Item WSMan:\\localhost\\Client\\TrustedHosts $value -Force
}
function SetTrustedHostsToAll
{
    SetTrustedHosts *
    LogEvent "Compelted SetTrustedHosts"
}

function GetTrustedHosts
{
    return (Get-Item WSMan:\\localhost\\Client\\TrustedHosts).Value
}

function GetAllHostManagementAddresses
{
    param($ncServersUri)

    $ips = @{}
    try
    {
        $result = Invoke-WebRequest -Uri $ncServersUri -UseDefaultCredentials -UseBasicParsing
        $servers = ($result.Content | ConvertFrom-Json).Value

        if (($servers -ne $null) -and ($servers.Count -gt 0))
        {
            foreach ($server in $servers)
            {
                $connections = $server.properties.connections.Where{$_.managementAddresses -ne $null -and $_.managementAddresses.Count -gt 0}
                if ($connections -ne $null -and $connections.Count -gt 0)
                {
                    $connection = $connections.Where{$_.credentialType -eq 'UsernamePassword'}
                    if ($connection -eq $null -or $connection.Count -eq 0)
                    {
                        $connection = $connections[0]
                    }
                    else
                    {
                        $connection = $connection[0]
                    }

                    $managementIPAddress = $connection.managementAddresses[0]

                    if (-not $ips.ContainsKey($managementIPAddress))
                    {
                        $ips.Add($managementIPAddress, $managementIPAddress)
                    }
                }
            }
        }
    }
    catch
    {
        $errorMessage = "Error occurred while getting Host Management IPs. Error: " + $_
        LogEvent $errorMessage
    }

    return $ips
}

function LogEvent
{
    param ($str)

    Log-Info -Message "$(Get-Date) : [SDN Validation] : $str"
}

function Log-Info
{
    param (
        [Parameter(ParameterSetName="default", Mandatory=$false)]
        [string]$Message,
        [Parameter(ParameterSetName="default", Mandatory=$false)]
        [switch]$ConsoleOut,
        [Parameter(ParameterSetName="default", Mandatory=$false)]
        [switch]$NoNewLine,
        [Parameter(ParameterSetName="default", Mandatory=$false)]
        [string]$Foreground
    )

    $maxRetries = 5
    for ($retry = 1; $retry -le $maxRetries; $retry++)
    {
        try
        {
            $param = @{}
            
            if ($NoNewLine)
            {
                $param.NoNewLine = $True
            }
            
            if ($Foreground)
            {
                $param.Foreground = $Foreground
            }
            
            Write-Host $Message @param
            
            break
        }
        catch
        {
            if ($retry -ge $maxRetries)
            {
                Write-Host "Failed to log. $_"
                Write-Host "Exception stacktrace:"
                Write-Host "$($_.ScriptStackTrace)"
            }
            else
            {
                Start-Sleep -Milliseconds 50
            }
        }
    }
}

logman delete ValidatorEtwTraceSession
logman create trace ValidatorEtwTraceSession -o trace.etl -p "{3CADFCE4-5E22-4102-BDC2-5AEA4198CD04}" -f bincirc -max 1000  
logman start ValidatorEtwTraceSession
ExecuteSDNValidationTests
logman stop ValidatorEtwTraceSession
