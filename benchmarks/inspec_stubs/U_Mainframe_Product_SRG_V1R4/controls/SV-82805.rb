control 'SV-82805' do
  title 'The Mainframe Product must limit privileges to change the Mainframe Product installation datasets to system programmers and authorized users in accordance with applicable access control policies.'
  desc 'If the application were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to applications with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'If an external security manager (ESM) is in use, examine the ESM configurations and rules.

If the ESM does not restrict update or greater access to installation datasets to system programmers or security managers or other authorized users as directed by applicable access control policies, this is a finding. 

If an ESM is NOT in use, examine the Mainframe Product installation and configuration settings.

If the Mainframe Product does not restrict update or greater access to Installation datasets to system programmers or security managers or other authorized users as directed by applicable access control policies, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to limit privileges to changing Mainframe Product installation datasets to system programmers or security managers or other authorized users as directed by applicable access control policies.

This can be accomplished with an ESM.

Configure the ESM to restrict update and greater access to Mainframe Product installation datasets  to system programmers or security managers or other authorized users in accordance with applicable access control policies.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68875r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68315'
  tag rid: 'SV-82805r1_rule'
  tag stig_id: 'SRG-APP-000133-MFP-000192'
  tag gtitle: 'SRG-APP-000133-MFP-000192'
  tag fix_id: 'F-74429r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
