control 'SRG-NET-000131-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must be configured to disable non-essential capabilities.'
  desc 'It is detrimental for Unified Communications Session Managers to provide, or enable by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors. Unified Communications Session Managers are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).'
  desc 'check', 'Verify the Unified Communications Session Manager is configured to disable non-essential capabilities.

If the Unified Communications Session Manager is not configured to disable non-essential capabilities, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to be configured to disable non-essential capabilities.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000131-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000131-VVSM-00101'
  tag rid: 'SRG-NET-000131-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000131-VVSM-00101'
  tag gtitle: 'SRG-NET-000131-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000131-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
