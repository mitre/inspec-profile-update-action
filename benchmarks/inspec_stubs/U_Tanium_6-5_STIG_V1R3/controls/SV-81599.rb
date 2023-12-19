control 'SV-81599' do
  title 'The Tanium application must authenticate all endpoint devices before allowing a network connection using bidirectional authentication that is cryptographically based.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of authentication claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide authentication decisions (as opposed to the actual authenticators) to the services that need to act on those decisions.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

Because of the challenges of applying this requirement of a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability.'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

Click on "Administration".

Select the "Global Settings" tab.

In the search box beside "Show Settings Containing:" type "sign_all_questions_flag". Enter.

If no results are returned, this is a finding since this setting needs to be explicitly set.

If results are returned for sign_all_questions_flag but the value is not "1", this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

Click on "Administration".

Select the "Global Settings" tab.

Click on "+ Add New Setting".

In "Create New Setting" dialog box, enter "sign_all_questions_flag" for "Setting Name:".

Enter "1" for "Setting Value:".

Select "Numeric" from "Value Type" drop-down list.

Select "Server" from "Affects" drop-down list.

Click “Save”.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67745r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67109'
  tag rid: 'SV-81599r1_rule'
  tag stig_id: 'TANS-SV-000034'
  tag gtitle: 'SRG-APP-000395'
  tag fix_id: 'F-73209r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
