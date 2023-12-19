control 'SV-240947' do
  title 'The vAMI must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.'
  desc 'Fail-secure is a condition achieved by the vAMI in order to ensure that in the event of an operational failure, the system does not enter into an unsecure state where intended security properties no longer hold. Preserving information system state information also facilitates system restart and return to the operational mode of the organization with less disruption of mission-essential processes.'
  desc 'check', 'Interview the ISSO and/or the SA.
 
Determine if the vAMI has ever not failed to a secure state during a system initialization failure, shutdown failure, or system abort.
 
If the vAMI has ever not failed to a secure state under these conditions, this is a finding.'
  desc 'fix', 'Reinstall the vRealize Automation instance as a complete package.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x vAMI'
  tag check_id: 'C-44180r676076_chk'
  tag severity: 'medium'
  tag gid: 'V-240947'
  tag rid: 'SV-240947r879640_rule'
  tag stig_id: 'VRAU-VA-000320'
  tag gtitle: 'SRG-APP-000225-AS-000166'
  tag fix_id: 'F-44139r676007_fix'
  tag 'documentable'
  tag legacy: ['SV-100887', 'V-90237']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
