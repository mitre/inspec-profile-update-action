control 'SV-6794' do
  title 'Attempts to access ports, protocols, or services that are denied are not logged..'
  desc 'Logging or auditing of failed access attempts is a necessary component for the forensic investigation of security incidents.  Without logging there is no way to demonstrate that the access attempt was made or when it was made.  Additionally a pattern of access failures cannot be demonstrated to assert that an intended attack was being made as apposed to an accidental intrusion.
The IAO/NSO will ensure that all attempts to any port, protocol, or service that is denied are logged.'
  desc 'check', 'The reviewer will, with the assistance of the IAO/NSO, verify that all attempts to any port, protocol, or service that is denied are logged.'
  desc 'fix', 'Develop a plan to implement the logging of failed or rejected ports, protocols or services requests.  The plan should include a projection of the storage requirements of the logged events.  Obtain CM approval of the plan and execute it.'
  impact 0.3
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2574r1_chk'
  tag severity: 'low'
  tag gid: 'V-6648'
  tag rid: 'SV-6794r1_rule'
  tag stig_id: 'SAN04.020.00'
  tag gtitle: 'Logging Failed Access to Port, Protocols, Services'
  tag fix_id: 'F-6251r1_fix'
  tag 'documentable'
  tag potential_impacts: 'If sufficient space is not allowed for logging or auditing, a denial of service or loss of data could be caused by overflowing the space allocated.'
  tag responsibility: ['Information Assurance Officer', 'Network Security Officer']
end
