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
