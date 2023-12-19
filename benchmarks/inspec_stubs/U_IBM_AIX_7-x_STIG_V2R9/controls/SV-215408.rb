control 'SV-215408' do
  title 'The /etc/shells file must exist on AIX systems.'
  desc 'The shells file (or equivalent) lists approved default shells. It helps provide layered defense to the security approach by ensuring users cannot change their default shell to an unauthorized unsecure shell.'
  desc 'check', 'AIX ships the following shells that should be considered as "approved" shells:

/bin/sh
/bin/bsh
/bin/csh
/bin/ksh
/bin/tsh
/bin/ksh93
/usr/bin/sh
/usr/bin/bsh
/usr/bin/csh
/usr/bin/ksh
/usr/bin/tsh
/usr/bin/ksh93
/usr/bin/rksh
/usr/bin/rksh93
/usr/sbin/uucp/uucico
/usr/sbin/sliplogin
/usr/sbin/snappd

ISSO/SA may install other shells. Ask ISSO/SA for other approved shells other than the shells shipped by AIX.

Check if file "/etc/shells" exists by running:

# ls -la /etc/shells 
rw-r--r--    1 bin      bin             111 Jun 01 2015  /etc/shells

If "/etc/shells" file does not exist, this is a finding.

Verify that "/etc/shells" only contains approved shells:

# cat /etc/shells
/bin/csh
/bin/ksh
/bin/psh
/bin/tsh
/bin/bsh
/usr/bin/csh
/usr/bin/ksh
/usr/bin/tsh
/usr/bin/bsh

If "/etc/shells" file contains a non-approved shell, this is a finding.

Check "/etc/security/login.cfg" for the shells attribute value of "usw:" stanza:

# lssec -f /etc/security/login.cfg -s usw -a shells
usw shells=/bin/sh,/bin/bsh,/bin/csh,/bin/ksh,/bin/tsh,/bin/ksh93,/usr/bin/sh,/usr/bin/bsh,/usr/bin/csh,/usr/bin/ksh,/usr/bin/tsh,/usr/bin/ksh93,/usr/bin/rksh,/usr/bin/rksh93,/usr/sbin/uucp/uucico,/usr/sbin/sliplogin,/usr/sbin/snappd

If the shells attribute value does not exist or is empty, this is a finding.
If the returned shells attribute value contains a shell that is not defined in "/etc/shells" file, this is a finding.
If the returned shells attribute value contains a non-approved shell, this is a finding.'
  desc 'fix', 'Run the following command to set shells attribute for stanza usw in "/etc/security/login.cfg": 
# chsec -f /etc/security/login.cfg -s usw -a shells=<list of approved shells separated by comma> 

Create the "/etc/shells" file and add all approved shells there, one shell per line: 
# vi /etc/shells

Change the ownership and mode-bit of "/etc/shells":
# chown bin.bin /etc/shells
# chmod 644 /etc/shells'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16606r294675_chk'
  tag severity: 'medium'
  tag gid: 'V-215408'
  tag rid: 'SV-215408r508663_rule'
  tag stig_id: 'AIX7-00-003110'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16604r294676_fix'
  tag 'documentable'
  tag legacy: ['SV-101737', 'V-91639']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
