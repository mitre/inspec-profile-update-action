control 'SV-16915' do
  title 'ESX Server is not properly registered in VMS.'
  desc 'The Vulnerability Management System (VMS) was developed to interface with the DOD Enterprise tools to assist all DOD CC/S/As in the identification of security vulnerabilities and track the issues through the lifecycle of the vulnerabilities existence. To ensure both the emerging and known vulnerabilities are addressed on a system, VMS tracks the existence of all potential vulnerabilities based on the posture of an asset. As a result, all vulnerabilities are tracked through their lifecycle.

Vulnerability Management is the process of ensuring that all network assets that are affected by an IAVM notice are addressed and corrected within a time period specified in the IAVM notice. VMS will notify commands, services, and agencies of new and potential security vulnerabilities. VMS meets the DoD mandate to ensure information system vulnerability alert notifications are received and acted on by all SAs. Keeping the inventory of assets current allows for tracking of virtualization servers and resources, and supports a successful IAVM process. The ability to track assets improves the effective use of virtualization assets, information assurance auditing efforts, as well as optimizing incident response times.'
  desc 'check', 'Use VMS and navigate to the site’s assets.  Ensure the ESX Server(s) are registered within VMS.  If they are not registered, this is a finding.'
  desc 'fix', 'Register ESX Servers in VMS.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16604r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15973'
  tag rid: 'SV-16915r1_rule'
  tag stig_id: 'ESX0863'
  tag gtitle: 'ESX Server is not properly registered in VMS'
  tag fix_id: 'F-15972r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
  tag ia_controls: 'VIVM-1'
end
