control 'SV-82953' do
  title 'The Mainframe Product must protect the confidentiality and integrity of all information at rest.'
  desc 'Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive and tape drive) within an organizational information system. Mobile devices, laptops, desktops, and storage devices can be either lost or stolen, and the contents of their data storage (e.g., hard drives and non-volatile memory) can be read, copied, or altered. Applications and application users generate information throughout the course of their application use.

This requirement addresses protection of user-generated data, as well as, operating system-specific configuration data. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate, in accordance with the security category and/or classification of the information.'
  desc 'check', 'Examine installation and configuration settings.

Verify that the Mainframe Product identifies product system-related files and user files for dataset/resource protection.

If the Mainframe Product is not configured to protect product system and user files for dataset/resources from unauthorized access, this is a finding.

If an external security manager (ESM) is in use, examine ESM configuration and rules.

If the configuration and rules do not protect product system-related files and user files for dataset resources from unauthorized access, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to protect the product system and user files for dataset/resources from unauthorized access in accordance with applicable access control policies.
 
This can be accomplished using an ESM.

Configure the ESM to restrict access to authorized users only in accordance with applicable access control policies.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68995r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68463'
  tag rid: 'SV-82953r1_rule'
  tag stig_id: 'SRG-APP-000231-MFP-000302'
  tag gtitle: 'SRG-APP-000231-MFP-000302'
  tag fix_id: 'F-74579r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
