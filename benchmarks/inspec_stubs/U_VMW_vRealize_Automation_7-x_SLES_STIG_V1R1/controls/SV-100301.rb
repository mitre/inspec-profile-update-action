control 'SV-100301' do
  title 'Files executed through a mail aliases file must be group-owned by root, bin, sys, or system, and must reside within a directory group-owned by root, bin, sys, or system.'
  desc 'If a file executed through a mail aliases file is not group-owned by root or a system group, it may be subject to unauthorized modification. Unauthorized modification of files executed through aliases may allow unauthorized users to attain root privileges.'
  desc 'check', 'Examine the contents of the /etc/aliases file:

# more /etc/aliases

Examine the aliases file for any directories or paths that may be utilized:

# ls -lL <file referenced from aliases>

Check the permissions for any paths referenced. 

If the group-owner of any file is not "root", "bin", "sys", or "system", this is a finding.'
  desc 'fix', 'Change the group-ownership of the file referenced from /etc/mail/aliases:

# chgrp root <file referenced from aliases>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89343r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89651'
  tag rid: 'SV-100301r1_rule'
  tag stig_id: 'VRAU-SL-000580'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-96393r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
