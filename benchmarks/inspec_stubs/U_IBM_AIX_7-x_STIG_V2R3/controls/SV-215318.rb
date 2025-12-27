control 'SV-215318' do
  title 'AIX must automatically lock after 15 minutes of inactivity in the CDE Graphical desktop environment.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled."
  desc 'check', %q(If CDE (X11) is not used on AIX, this is Not Applicable.

From the command prompt, run the following script:
for file in /usr/dt/config/*/sys.resources; do
  etc_file=`echo $file | sed -e s/usr/etc/`
  echo "\nChecking config file "$etc_file"..."
  if [[ ! -f $etc_file ]]; then
    echo "Missing config file "$etc_file
  else
    cat $etc_file |grep 'dtsession\*saverTimeout:'
    cat $etc_file |grep 'dtsession\*lockTimeout:'
  fi
done

The above script should yield the following output:
Checking config file /etc/dt/config/C/sys.resources...
Missing config file /etc/dt/config/C/sys.resources

Checking config file /etc/dt/config/POSIX/sys.resources...
dtsession*saverTimeout: 15
dtsession*lockTimeout: 30

Checking config file /etc/dt/config/en_US/sys.resources...
dtsession*saverTimeout: 15
dtsession*lockTimeout: 25

If the result of the script shows any config file missing, or any of the "dtsession*saverTimeout" or "dtsession*lockTimeout" values are greater than "15", this is a finding.)
  desc 'fix', %q(From the command prompt, run the following script to set the default timeout parameters "dtsession*saverTimeout:" and "dtsession*lockTimeout:" as "15" minutes: 
for file in /usr/dt/config/*/sys.resources; do
  etc_file=`echo $file | sed -e s/usr/etc/`
  echo "\nupdating config file "$etc_file"..."
  if [[ ! -f $etc_file ]]; then
    dir=`dirname $file | sed -e s/usr/etc/`
    mkdir -p $dir
    echo 'dtsession*saverTimeout: 15' >> $dir/sys.resources
    echo 'dtsession*lockTimeout: 15' >> $dir/sys.resources
  else
    cp $etc_file $etc_file.bak
    cat $etc_file | grep -v 'dtsession\*saverTimeout:' > $etc_file.sav
    cat $etc_file.sav | grep -v 'dtsession\*lockTimeout:' > $etc_file
    echo 'dtsession*saverTimeout: 15' >> $etc_file
    echo 'dtsession*lockTimeout: 15' >> $etc_file
  fi
done)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16516r294405_chk'
  tag severity: 'medium'
  tag gid: 'V-215318'
  tag rid: 'SV-215318r508663_rule'
  tag stig_id: 'AIX7-00-003000'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-16514r294406_fix'
  tag 'documentable'
  tag legacy: ['SV-101333', 'V-91233']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
