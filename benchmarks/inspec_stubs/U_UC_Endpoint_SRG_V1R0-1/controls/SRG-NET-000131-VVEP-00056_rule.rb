control 'SRG-NET-000131-VVEP-00056_rule' do
  title 'The Unified Communications Endpoint must be configured to disable or remove nonessential capabilities.'
  desc 'It is detrimental for Unified Communications Endpoints when unnecessary features are enabled by default. Often these features are enabled by default with functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Network elements are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).'
  desc 'check', 'Verify the Unified Communications Endpoint is configured to disable or remove nonessential capabilities. Nonessential capabilities would include peer services and other functions not directly pertaining to Unified Communications Endpoint functionality.

If the Unified Communications Endpoint cannot be configured to disable or remove nonessential capabilities, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to disable or remove nonessential capabilities.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000131-VVEP-00056_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000131-VVEP-00056'
  tag rid: 'SRG-NET-000131-VVEP-00056_rule'
  tag stig_id: 'SRG-NET-000131-VVEP-00056'
  tag gtitle: 'SRG-NET-000131-VVEP-00056'
  tag fix_id: 'F-SRG-NET-000131-VVEP-00056_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
