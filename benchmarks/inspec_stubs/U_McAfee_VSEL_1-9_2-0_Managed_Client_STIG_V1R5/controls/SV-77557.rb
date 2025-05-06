control 'SV-77557' do
  title 'The nails user and nailsgroup group must be restricted to the least privilege access required for the intended role.'
  desc 'The McAfee VirusScan Enterprise for Linux software runs its processes under the nails user, which is part of the nailsgroup group. The WEB GUI is also accessed using the nails user. Ensuring this account only has access to the required functions necessary for its intended role will mitigate the possibility of the nails user/nailsgroup group from being used to perform malicious destruction to the system in the event of a compromise.'
  desc 'check', 'Access the Linux system console command line as root.

Execute the following commands. This command will pipe the results to text files for easier review. 

find / -group nailsgroup >nailsgroup.txt
find / -user nails >nails.txt

Execute the following commands to individually review each of the text files of results, pressing space bar to move to each page until the end of the exported text. 

more nailsgroup.txt
more nails.txt

When reviewing the results, verify the nailsgroup group and nails user only own the following paths. The following paths assume an INSTALLDIR of /opt/NAI/LinuxShield and a RUNTIMEDIR of /var/opt/NAI/LinuxShield. If alternative folders were used, replace the following paths accordingly when validating.

/var/opt/NAI and sub-folders
/opt/NAI and sub-folders
/McAfee/lib
/var/spool/mail/nails
/proc/##### (where ##### represents the various process IDs for the VSEL processes.)

If any other folder is owned by either the nailsgroup group or the nails user, this is a finding.'
  desc 'fix', 'Access the Linux system console command line as root.

Navigate to each path to which the nails user or nailsgroup group has unnecessary permissions/ownership.

Using the chmod command, reduce or remove permissions for the nails user.

Using the chown command to remove ownership by the nails user or nailsgroup group.'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Managed Client'
  tag check_id: 'C-63819r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63067'
  tag rid: 'SV-77557r1_rule'
  tag stig_id: 'DTAVSEL-202'
  tag gtitle: 'SRG-APP-000340'
  tag fix_id: 'F-68985r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
