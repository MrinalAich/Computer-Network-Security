
attackerIP="192.168.102.102"
victimIP="192.168.103.103"

for port in {5555..5564}
do
   echo "iperf -c $victimIP -p $port -B $attackerIP"
   eval 'iperf -c $victimIP -p $port -B $attackerIP &'
done
