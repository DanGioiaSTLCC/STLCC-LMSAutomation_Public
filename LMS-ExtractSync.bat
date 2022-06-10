REM this script syncs a folder over scp
REM  to work, remote server must have key of local user for auth
@echo off
REM setup paths
set ServerName=hostname.domain..local
set RemotePath=/linux/local/path
set LocalPath=\TEMP\WinlocalPath\
set LocalPathFull=%systemdrive%%LocalPath%
REM create local path if it doesn't exist
if not exist %LocalPathFull% (mkdir %LocalPathFull%)
cd %LocalPathFull%
REM copy down the files
@echo on
scp -p %username%@%ServerName%:%RemotePath%/* %LocalPathFull%
@echo finished.