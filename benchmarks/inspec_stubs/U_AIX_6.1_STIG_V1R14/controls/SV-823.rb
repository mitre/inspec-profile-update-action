control 'SV-823' do
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
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28612r1_chk'
  tag severity: 'medium'
  tag gid: 'V-823'
  tag rid: 'SV-823r2_rule'
  tag stig_id: 'GEN003760'
  tag gtitle: 'GEN003760'
  tag fix_id: 'F-977r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
