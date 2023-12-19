control 'SV-228879' do
  title 'The Palo Alto Networks security platform must inspect inbound and outbound SMTP and Extended SMTP communications traffic (if authorized) for protocol compliance and protocol anomalies.'
  desc 'Application protocol anomaly detection examines application layer protocols such as SMTP to identify attacks based on observed deviations in the normal RFC behavior of a protocol or service. This type of monitoring allows for the detection of known and unknown exploits that exploit weaknesses of commonly used protocols. The device must be configured to inspect inbound and outbound SMTP and Extended SMTP communications traffic to detect protocol anomalies such as malformed message and command insertion attacks.'
  desc 'check', 'If SMTP or ESMTP is authorized, ask the Administrator which Security Policy inspects authorized SMTP and ESMTP traffic.
Go to Policies >> Security
Select the identified Security Policy.

If the "Profile" column does not display the "Antivirus Profile" symbol, this is a finding.

If the "Profile" column does not display the "Vulnerability Protection Profile" symbol, this is a finding.'
  desc 'fix', 'If SMTP or ESMTP is authorized, configure a security policy to allow it and inspect it.
Go to Policies >> Security
Select "Add" to create a new security policy or select the name of the security policy to edit it.
In the "Security Policy Rule" window, complete the required fields.
In the "Name" tab, complete the "Name" and "Description" fields.
In the "Source" tab, complete the "Source Zone" and "Source Address" fields.
In the "User" tab, complete the "Source User" and "HIP Profile" fields.
In the "Destination" tab, complete the "Destination Zone" and "Destination Address" fields.
In the "Applications" tab, either select the "Any" check box or add SMTP.  Configured filters and groups can be selected if the group includes SMTP.
In the "Actions" tab, select "allow".  
In the "Actions" tab in the "Profile Setting" section; in the "Profile Type" field, select "Profiles".  The window will change to display the different categories of Profiles.  
In the "Profile Setting" section; in each of the "Profile" fields, select the configured Profile.
Note: An Antivirus Profile and an Antispyware Profile are required.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31114r513932_chk'
  tag severity: 'medium'
  tag gid: 'V-228879'
  tag rid: 'SV-228879r557387_rule'
  tag stig_id: 'PANW-AG-000147'
  tag gtitle: 'SRG-NET-000512-ALG-000064'
  tag fix_id: 'F-31091r513933_fix'
  tag 'documentable'
  tag legacy: ['V-62639', 'SV-77129']
  tag cci: ['CCI-000366', 'CCI-001125']
  tag nist: ['CM-6 b', 'SC-7 (17)']
end
