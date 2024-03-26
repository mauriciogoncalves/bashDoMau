#!/bin/bash 
touch /script_logs/test.log
MaxFileSize=2048
  
file_size=`du -b /script_logs/test.log | tr -s '\t' ' ' | cut -d' ' -f1`

if [ $file_size -gt $MaxFileSize ];then   
    timestamp=`date +%s`
    mv /script_logs/test.log /script_logs/test.log.$timestamp
    touch /script_logs/test.log
fi
 
