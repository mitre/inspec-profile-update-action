control 'SV-226911' do
  title 'The services file must be owned by root or bin.'
  desc "Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the ownership of the services file.

Procedure:
# ls -lL /etc/services

If the services file is not owned by root or bin, this is a finding.'
  desc 'fix', 'Change the ownership of the services file to root or bin.

Procedure:
# chown root /etc/services'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29073r485020_chk'
  tag severity: 'medium'
  tag gid: 'V-226911'
  tag rid: 'SV-226911r603265_rule'
  tag stig_id: 'GEN003760'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29061r485021_fix'
  tag 'documentable'
  tag legacy: ['V-823', 'SV-823']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
