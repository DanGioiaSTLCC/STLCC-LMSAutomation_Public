# Notes for syncing Canvas Data2

## Database
* scripts assume postgres database running on local server
* database writing username is only allowed to connect from local server

## Configure for remote access
1. Create a new user to own canvas db: `CREATE USER newusername WITH PASSWORD 'passwordtext';`
1. Create a new user to read results: `CREATE USER newusername WITH PASSWORD 'passwordtext' IN GROUP pg_read_all_data;`
1. Connect to local database server: `psql -U canvasdata -h 127.0.0.1 -d canvas`
1. Configure postgres certificate  
1. Configure postgres for tls only  
1. Open local firewall for postgres port

Create the canvas database user
```sql
CREATE ROLE canvasdata WITH
  LOGIN
  NOSUPERUSER
  INHERIT
  CREATEDB
  NOCREATEROLE
  NOREPLICATION
  NOBYPASSRLS
  ENCRYPTED PASSWORD 'SCRAM-SHA-256$4096:encrypted=and=encoded';
```

Create the canvas database
```sql
CREATE DATABASE canvas
    WITH OWNER = canvasdata
    ENCODING = 'UTF8'
    LC_COLLATE = 'en_US.UTF-8'
    LC_CTYPE = 'en_US.UTF-8'
    TEMPLATE template0;
```

TLS certificates
```bash
# generate certificate info
openssl req -new -x509 -days 365 -nodes -text -out server.crt -keyout server.key -subj "/CN=host.domain.tld"
# copy the certificate info to the postgres app location
sudo cp server.{key,crt} /var/lib/pgsql/data/.
# modify ownership and permissions for certificate information
sudo chown postgres:postgres /var/lib/pgsql/data/server.{key,crt}
sudo chmod 0400 /var/lib/pgsql/data/server.key
# enable service to autostart
sudo systemctl enable postgresql.service
```

Firewall configuration
```bash
sudo firewall-cmd --zone=public --permanent --add-service=postgresql
sudo firewall-cmd --reload
```

## Configuration Files

postgresql.conf (update these items:)
```ini
password_encryption = scram-sha-256
ssl = on
listen_addresses = '*'
max_connections = 100
```

pg_hba.conf
```ini
# TYPE  DATABASE        USER            ADDRESS                 METHOD

# "local" is for Unix domain socket connections only
local   all             all                                     peer

# IPv4 local connections:
host       all         all              127.0.0.1/32          scram-sha-256
hostssl	   canvas      RWUser           IPAddress/CIDR        scram-sha-256
hostssl    canvas      RUser1           IPAddress/CIDR        scram-sha-256
hostssl    canvas      RUser2           IPAddress/CIDR        scram-sha-256

# IPv6 local connections:
hostssl    all         all             ::1/128                scram-sha-256
```

# Synchronizing
## WSL configuration
```powershell
# install the LTS version of Ubuntu
wsl --install Ubuntu-24.04
```
```bash
# in Linux, update the OS
sudo apt-get update
sudo apt-get upgrade
# install nala for better UI in future installs and updates
sudo apt install nala
# setup python and python components
sudo nala install python3-pip python3-pip-whl python3-venv jq
# setup pyton virt environment and install dap client
python3 -m venv dap2
. ./dap2/bin/activate
pip3 install instructure-dap-client[postgresql]
```

## CD2 Table Syncing
* Tables must be initialized (`dap initdb --namespace canvas --table TABLENAME`) prior to running the syncdb scripts
* users needs to be added to cron user list if scheduled in lx
* script files need to be marked as executable

Create a file with the configured environment variables: `nano ./.dap_details`
```bash
export DAP_API_URL='https://api-gateway.instructure.com'
export DAP_CLIENT_ID='region#rest_of_client_id'
export DAP_CLIENT_SECRET='client_secret'
export DAP_CONNECTION_STRING='postgresql://dbuser:dbpass@host:5432/dbname'
```
### Table Initialization
Tables must be initialized (`dap initdb --namespace canvas --table TABLENAME`) prior to running the syncdb scripts
```bash
    . .dap_details
    . ./dap2/bin/activate
    TABLES=$(dap --non-interactive list --namespace canvas)
    for TABLE in $TABLES; do dap initdb --namespace canvas --table "$TABLE"; done
```

### Table Syncing
Create a sync script: `nano ./dap_sync.sh`
``` bash
#!/bin/bash
# ## ###
# configuration
mgmtdir=$HOME
pyEnv="$mgmtdir/dap2"
NameSpaces=("canvas" "new_quizzes")
# ## ###
# definitions
# construct log file path
today=$(date +%F)
now=""
syncLogLocation="$mgmtdir/cd2logs/"
syncLogFile="${syncLogLocation}canvas-cd2-${today}.log"

# timestamp to use in log
update_now() { now=$(date +%F_%T); }

# sync database tables based on table name and command info received from dap command
sync_tables_bydblist() {
    # friendly up the parameters
    namespace=$1
    refDir=$2
    logfile=$3
    localonly=${4:''}
    listoptions='--omit-record-count'
    # if local only option specified, only list already replicated tables
    if [[ $localonly == *"local"* ]]; then
        listoptions = "${listoptions} --omit-not-replicated"
    fi
    # retrieve CD2 table sync info
    update_now
    echo "[$now] Starting sync of ${namespace^^} ####" >> $logfile
    echo "[$now] getting ${namespace^^} table sync status from database" >> $logfile
    dbListData=$(dap --non-interactive listdb $listoptions --namespace $namespace)
    # count table info
    TableCount=$(echo $dbListData | jq '. | length')
    # iterate through table info and execute relevant sync command
    for (( i=0; i < $TableCount; i++ )); do
        update_now
        itemI=$(echo $dbListData | jq  ".[${i}]")
        tblI=$(echo $itemI | jq '.name' -r)
        cmdI=$(echo $itemI | jq '.command' -r)
        echo "[$now] Starting $cmdI for $tblI ..." >> $logfile
        dap --loglevel error --logfile $logfile $cmdI --namespace $namespace --table $tblI
        update_now
        echo "[$now] Finished with $cmdI for $tblI" >> $logfile
    done
    echo "[$now] Finished ${namespace^^} table sync ##" >> $logfile
}
# ## ###
# action start
# output log file path if watching terminal
echo "LOG: $syncLogFile"
# load the dap client details
source $mgmtdir/.dap_details
# python virtual env activation to enable the Instructure DAP client
source $pyEnv/bin/activate
# sync the tables for each namespace in the configuration
for ns in ${!NameSpaces[@]}
do
    sync_tables_bydblist ${NameSpaces[$ns]} $mgmtdir $syncLogFile
done

# deactivate python virtual env
deactivate

# copy log file to windows filesystem
cp $syncLogFile /mnt/e/cd2logs/

```
Enable the sync script for execution: `chmod +x dap_sync.sh`

Schedule the powershell script to run using the task scheduler
```powershell
# run sync bash script in WSL Linux environment
wsl /home/canvascd2/dap_sync.sh

# log info
$logDirectory = "E:\cd2logs\"
$today = Get-Date -uFormat %Y-%m-%d
$todayLogFile = $logDirectory + "canvas-cd2-" + $today.ToString() + ".log"
$LogBody = Get-Content -Path $todayLogFile -Raw

# send completion notification
Send-MailMessage -SmtpServer "host.domain.tld" -To "recipient@domain.tld" -From "sender@domain.tld" -Body $LogBody -Subject "Canvas - CD2 Sync Fininshed"
```