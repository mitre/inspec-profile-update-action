control 'SV-37543' do
  title 'The system must be checked for extraneous device files at least weekly.'
  desc 'If an unauthorized device is allowed to exist on the system, there is the possibility the system may perform unauthorized operations.'
  desc 'check', 'Determine if there are any device files outside of /dev:
# find / -type b -o -type c |more

Check for the presence of an aide on the system:
# rpm -qa | grep aide

If aide is not installed, ask the SA what file integrity tool is being used to check the system.

Check the global crontabs for the presence of an "aide" job to run at least weekly, if aide is installed. Otherwise, check for the presence of a cron job to run the alternate file integrity checking application.

# grep aide /etc/cron*/*

If a tool is being run, then the configuration file for the appropriate tool needs to be checked for selection lines for /dev and any other directories/subdirectories that contain device files.

Review the process to determine if the system is checked for extraneous device files on a weekly basis.

If no weekly automated or manual process is in place, this is a finding.

If the process is not identifying extraneous device files, this is a finding.'
  desc 'fix', 'Establish a weekly automated or manual process to create a list of device files on the system and determine if any files have been added, moved, or deleted since the last list was generated.

A list of device files can be generated with this command:
# find / -type b -o -type c > device-file-list'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36198r4_chk'
  tag severity: 'low'
  tag gid: 'V-923'
  tag rid: 'SV-37543r3_rule'
  tag stig_id: 'GEN002260'
  tag gtitle: 'GEN002260'
  tag fix_id: 'F-31458r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000318']
  tag nist: ['CM-3 f']
end
