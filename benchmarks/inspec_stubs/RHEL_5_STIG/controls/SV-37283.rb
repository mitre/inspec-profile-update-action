control 'SV-37283' do
  title 'All global initialization files must be owned by root.'
  desc "Global initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'fix', 'Change the ownership of global initialization files with incorrect ownership.

Procedure:
# chown root <global initialization files>

or:
# ls etc/bashrc /etc/csh.cshrc /etc/csh.login /etc/csh.logout /etc/environment /etc/ksh.kshrc /etc/profile /etc/suid_profile /etc/profile.d/* 2>null|xargs stat -L -c %U:%n|egrep -v "^root"|cut -d: -f2|xargs chown root
will set the owner of all files not currently owned by root to root.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-11982'
  tag rid: 'SV-37283r1_rule'
  tag stig_id: 'GEN001740'
  tag gtitle: 'GEN001740'
  tag fix_id: 'F-31229r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
