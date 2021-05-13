#V1.1
#=================================== functions ======================================
function Create-AesManagedObject($key, $IV) {
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($key) {
        if ($key.getType().Name -eq "String") {
            $aesManaged.Key = [system.Text.Encoding]::UTF8.GetBytes($key)
        }
        else {
            $aesManaged.Key = $key
        }
    }
    if ($IV) {
        if ($IV.getType().Name -eq "String") {
            $aesManaged.IV = [system.Text.Encoding]::UTF8.GetBytes($IV)
        }
        else {
            $aesManaged.IV = $IV
        }
    }
    $aesManaged
}
 
function Encrypt-Bytes($key, $unencryptedBytes) {
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $BlockSize = 128 # = algorithm blocksize
    $Bytesize = $unencryptedBytes.Length
    $BytesOffset = 0
    [byte[]]$encryptedBody = new-object byte[]($Bytesize-($Bytesize % $BlockSize)) #multiple of BlockSize
    [byte[]]$encryptedFinal = new-object byte[]($Bytesize % $BlockSize) #remaining part
    
    do { 
        #get a chunk of data out of the file and into byte array buffer   
        if ($BytesOffset + $BlockSize -gt $ByteSize){
            #last chunk 
            $encryptedFinal = $encryptor.TransformFinalBlock($unencryptedBytes, $Bytesoffset, $encryptedFinal.Length)
        } 
        else{
            [void]$encryptor.TransformBlock($unencryptedBytes, $BytesOffset, $BlockSize, $encryptedBody, $BytesOffset)
        }
        $BytesOffset += $BlockSize
    }
    while ($BytesOffset -lt $ByteSize)

    [byte[]] $fullData =  $aesmanaged.iv + $encryptedBody + $encryptedFinal
    $aesManaged.Dispose()
    
    $fullData
}

enum logginglevel{
    all = 6
    debug = 5
    info = 4
    warning = 3
    error = 2
    fatal = 1
    off = 0}
function Write-Log {
     [CmdletBinding()]
     param(
         [Parameter()][ValidateNotNullOrEmpty()][string]$Message,
         [Parameter()][ValidateNotNullOrEmpty()][logginglevel]$loglevel = [logginglevel]::info
     )
    
    if ($loglevel -le $apploglevel){
        $logline = "$(Get-Date -f G) ($loglevel) $Message"
        Write-Host $logline
        $logline | Add-Content $logfilepath
        #Rename the logfile in case exceeds max size
        if (((Get-Item $logfilepath).Length -gt $logmaxsize)){
            Rename-Item $logfilepath $logfilepath.Replace(".log","_$((get-date).ToString("MMddyyyy_HHmm")).log")
        }
     }
 }

Function SendErrorMail([string]$errormsg){
    $from = ""
    $to = ""
    $smtp = "0.0.0.0"
    $port = 9925
    $subject = "$($env:COMPUTERNAME) : Send backup error"
    $body = "`r`nMessage from server $($env:COMPUTERNAME)`r`nScheduled backup did not completed successfully.`r`n$errormsg"
    try{
        Send-MailMessage -From $from -To $to -Subject $subject -Body $Body -SmtpServer $smtp -Port $port
        Write-Log "Successfully sent error mail to $to from $from using $smtp SMTP." info
    }
    catch{
        Write-Log "Cannot send mail to $to from $from using $smtp SMTP." error
    }
}
#=================================== End functions ======================================

Add-Type -assembly "system.io.compression.filesystem"
$TempDestination = "$(Split-Path $MyInvocation.MyCommand.Path)\Temp"
if (!(Test-Path $TempDestination)){[void](New-Item -Path $(Split-Path $MyInvocation.MyCommand.Path) -Name "Temp" -ItemType "directory")}
$loginForm = '
{   "user" : "",
    "password" : ""
}'
$Keystring = ""
$APIUpload = "upload"#enc"
$APILogin = "login"
$ConfigName = "BackupCerve.config"
$apploglevel = [logginglevel]::info #LogLevel and LogSize are loaded from config file, but we need to set them before the load to log config load
$computersn = (get-ciminstance -classname win32_bios).SerialNumber
$hostname = $env:COMPUTERNAME
$logfilepath = ("$(Split-Path $MyInvocation.MyCommand.Path)\$(($MyInvocation.MyCommand.Name).Replace('.ps1',''))_$hostname-$computersn.log")
$logmaxsize = 10Mb
try{
    [xml]$BP = Get-Content "$(Split-Path $MyInvocation.MyCommand.Path)\$ConfigName" -ErrorAction Stop
    Write-Log "Successfully loaded config file $(Split-Path $MyInvocation.MyCommand.Path)\$ConfigName" debug
    $APIUrl = $BP.Configuration.Server.Endpoint
    $site = $BP.Configuration.Site.Name
}
catch{
    Write-Log "Critical: cannot load config from $(Split-Path $MyInvocation.MyCommand.Path)\$ConfigName): $($_.Exception.Message) " error
    exit
}

$apploglevel = [logginglevel]$BP.Configuration.Logging.Level
$logmaxsize = ([Int]$BP.Configuration.Logging.MaxSize) * 1Mb

Write-Log "Paramaters: ApiUrl=$ApiUrl site=$site TempDestination=$TempDestination APIUpload=$APIUpload APILogin=$APILogin apploglevel=$apploglevel logfilepath=$logfilepath logmaxsize=$logmaxsize" debug
Write-Log "CerveBackup starting - endpoint:$ApiUrl loglevel:$apploglevel"
#===================================================================================================================
$PostIt = ""
$WarnMess = ""
#build up filepath
$BackupFilePath = "$(Split-Path $MyInvocation.MyCommand.Path)\$($site)_$($hostname)_$($computersn)_$((Get-Date).ToString('yyyyMMdd')).zip"
if (Test-Path $BackupFilePath){Remove-Item $BackupFilePath; Write-Log "Removing old BackupFile $BackupFilePath" debug}
#Clean Temp folder
Write-Log "Cleaning $TempDestination" debug
Remove-Item $TempDestination\* -Force
#Zip Folders
$BkpFoldersNum = 0
if ($BP.Configuration.Site.Folders.Enabled -eq "True"){
    $FoldersFound = @{};
    Write-Log "Folders backup option enabled. Processing $($BP.Configuration.Site.Folders.Folder.count) items" debug
    foreach ($Folder in $BP.Configuration.Site.Folders.Folder){
        if ($Folder.Path -like '*`**'){
            $SubFolders = Get-ChildItem $Folder.Path.Split('*')[0] -Directory
            ForEach ($sf in $SubFolders.Name){
                $foldeExp=[System.Environment]::ExpandEnvironmentVariables("$($Folder.Path.Split('*')[0])$sf$($Folder.Path.Split('*')[1])")
                if (Test-Path $foldeExp){
                    $FoldersFound.add("$($Folder.Name)_$sf",$foldeExp)
                }else{
                    Write-Log "Folder $foldeExp does not exist. Skipping" warning
                }
            }
        }else{
            $foldeExp=[System.Environment]::ExpandEnvironmentVariables($Folder.Path)
            if (test-path $foldeExp){
                $FoldersFound.add($Folder.Name, [System.Environment]::ExpandEnvironmentVariables($Folder.path))
            }else{
                Write-Log "Folder $foldeExp does not exist. Skipping" warning
            }
        }
    }

    foreach($FolderFound in $FoldersFound.keys){
        Write-Log "Zipping folder $($FolderFound)" debug
        $ec = $error.count
        [io.compression.zipfile]::CreateFromDirectory($FoldersFound[$FolderFound], "$TempDestination\$($FolderFound).zip") 
        if ($error.Count -gt $ec){
            Write-Log "Error while zipping folder $($FolderFound): $($error[0])" error
            if (Test-Path $TempDestination\$($FolderFound).zip){
                $PostIt += "Warning on folder backup $($FolderFound). This error was raised during processing: $($error[0])"
                Write-Log "Attaching PostIt to Backup for folder $($FolderFound)" debug
            }
            else{Write-Log "No backup of $($FolderFound) was created." error; break}
        }
        $BkpFoldersNum++
    }
}

$BkpFilesNum = 0
if ($BP.Configuration.Site.Files.Enabled -eq "True"){
    Write-Log "Files backup option enabled. Processing $($BP.Configuration.Site.Files.File.count) items" debug
    foreach ($File in $BP.Configuration.Site.Files.File){
        $fileExp=[System.Environment]::ExpandEnvironmentVariables($File.Path)
        if (test-path $fileExp){
            Write-Log "Zipping file $($File.name)" debug
            $ec = $error.count
            [System.IO.Compression.ZipArchive]$ZipFile = [System.IO.Compression.ZipFile]::Open("$TempDestination\$($File.name).zip", ([System.IO.Compression.ZipArchiveMode]::Create))
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($ZipFile, $fileExp, (Split-Path $fileExp -Leaf))
            $ZipFile.Dispose()
            if ($error.Count -gt $ec){
                Write-Log "Error while zipping file $($File.name): $($error[0])" error
                if (Test-Path $TempDestination\$($File.name).zip){
                    $PostIt += "Warning on file backup $($File.name). This error was raised during processing: $($error[0])"
                    Write-Log "Attaching PostIt to Backup for file $($File.name)" debug
                }
                else{Write-Log "No backup of $($File.name) was created." error; break}
            }
            $BkpFilesNum++
        }else{
            Write-Log "Folder $foldeExp does not exist. Skipping" warning
        }
    }
}

$BkpDBsNum = 0
if ($BP.Configuration.Site.Database.Enabled -eq "True"){
    $DumpFile = $([System.Environment]::ExpandEnvironmentVariables($BP.Configuration.Site.Database.DumpFilePath))
    Write-Log "Database dump option enabled. Start dumping. Destination file: $Dumpfile" debug 
    if (Test-Path $Dumpfile){Remove-Item $Dumpfile; Write-Log "Removing old dump $Dumpfile" debug}
    $ProcessInfo = New-object System.Diagnostics.ProcessStartInfo 
    $ProcessInfo.CreateNoWindow = $true 
    $ProcessInfo.UseShellExecute = $false 
    $ProcessInfo.RedirectStandardOutput = $true 
    $ProcessInfo.RedirectStandardError = $true
    $ProcessInfo.FileName = [System.Environment]::ExpandEnvironmentVariables($BP.Configuration.Site.Database.DumpCommandPath)
    $Args = @()
    foreach($Arg in $BP.Configuration.Site.Database.DumpCommandArguments.Argument){
        $Args+=$Arg
    }
    $ProcessInfo.Arguments = $Args
    Write-Log "Dumping process parameters: $Processinfo" debug
    $DumpProcess = New-Object System.Diagnostics.Process 
    $DumpProcess.StartInfo = $ProcessInfo
    $ProcessError = ""
    try {[void]$DumpProcess.Start()
        Do{
            $DumpProcess.StandardOutput.ReadLine() | Add-Content $DumpFile
            #$ProcessError += $DumpProcess.StandardError.ReadLine()
        } 
        while (!$DumpProcess.HasExited)
        if (($DumpProcess.ExitCode -eq 0) -and (Test-Path $DumpFile)){
            Write-Log "DB successfully dumped, moving dumpfile $DumpFile in $TempDestination" debug
            Move-Item $DumpFile $TempDestination
            $BkpDBsNum++
        }
        else {
            $ProcessError += $DumpProcess.StandardError.ReadLine()
            throw $ProcessError
        }
    }
    catch{
        if ($ProcessError -eq ""){
            $ProcessError = $Error[0]
        }
        Write-Log "Something went wrong while dumping DB: $ProcessError. Attaching PostIt to Backup" error
        $PostIt += "Dump of $DumpFile failed with error: $ProcessError"
    }
}
if ($BkpFoldersNum+$BkpDBsNum+$BkpFilesNum -gt 0){
    if ($PostIt.Length -ne 0){
        $PostIt | Add-Content "$TempDestination\Warning_README.txt"
        $WarnMess = "Warning there were errors during backup. Read the PostIt attached to backup file."
    }    
}
else {
    $PostIt | Add-Content "$TempDestination\CriticalError_README.txt"
    $WarnMess = "Critical error during backup. Read the PostIt attached to backup file."
    Write-Log "Critical: nothing backed up. Exiting" error
}
#Including logs in backup
try{
    Copy-Item ("$(Split-Path $MyInvocation.MyCommand.Path)\$($MyInvocation.MyCommand.Name).log").Replace(".ps1","*") $TempDestination
}
catch{}

Write-Log "Zipping $TempDestination into $BackupFilePath" debug
[io.compression.zipfile]::CreateFromDirectory($TempDestination,$BackupFilePath)
<#Encrypt to file
$BackupBytes = Get-Content $BackupFilePath -AsByteStream
$EncryptedBytes = Encrypt-Bytes $Keystring $BackupBytes
Write-Log "Encrypted $($EncryptedBytes.length) bytes of data" info
Set-Content "$($BackupFilePath).enc" -value $EncryptedBytes -AsByteStream
Write-Log "Encrypted $($EncryptedBytes.length) bytes of data and saved to $($BackupFilePath).enc" debug
#>

#********************************* uploading Section
#Login to API Service to grab the Token
Write-Log "Setting ServerCertificateValidationCallback to true (disabling cert validation check)"debug
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} 

$APIReply = Invoke-RestMethod -Method post -Uri "$APIUrl/$APILogin" -ContentType "application/json" -Body $loginform -SkipCertificateCheck
if ($APIReply.auth -eq "true"){
    $headers = @{"Authorization"=$APIReply.token}
    Write-Log "Succesfully received token from endpoint $ApiUrl" info
}
else {
    $errormsg = "Login to API Service failed. Cannot upload file. Exiting."
    Write-Log $errormsg error
    #SendErrorMail $errormsg
    Exit 1
}

$win32bios = get-ciminstance -classname win32_bios
$hostname = $env:COMPUTERNAME
$serialnumber = $win32bios.serialnumber
$manufacturer = $win32bios.Manufacturer

#Form for uploading file. DestFolder must match the Import Service Folder on the SnowSLM Server
$UploadForm = @{
    bkpfile = get-item -path "$($BackupFilePath)"#.enc"
    cn = $hostname
    sn = $serialnumber
    vendor = $manufacturer
    site = $site
}
#Post Request for file upload
$APIReply = Invoke-RestMethod -Method post -Uri "$APIUrl/$APIUpload" -Headers $headers -form $UploadForm -SkipCertificateCheck
if ($APIReply -notlike "true"){
    $errormsg = "Upload API Service failed. Exiting."
    Write-Log $errormsg error
    #SendErrorMail $errormsg
    Exit 1
}
else{
   Write-log "Successfully uploaded backup file to $APIUrl/$APIUpload destination site $site with $BkpFilesNum files, $BkpFoldersNum folders and $BkpDBsNum database dumps.$WarnMess" info
   if (test-path "$($BackupFilePath).enc") {Remove-Item "$($BackupFilePath).enc";Write-log "Removed file $($BackupFilePath).enc" debug}
   if (test-path $BackupFilePath) {Remove-Item $BackupFilePath;Write-log "Removed file $BackupFilePath" debug}
}