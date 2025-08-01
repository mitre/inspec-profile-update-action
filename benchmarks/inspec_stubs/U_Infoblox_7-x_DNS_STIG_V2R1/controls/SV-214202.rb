control 'SV-214202' do
  title 'The Zone Signing Key (ZSK) rollover interval must be configured to less than two months.'
  desc "An attacker that has compromised a ZSK can use that key only during the KSK's signature validity interval. An attacker that has compromised a KSK can use that key for only as long as the signature interval of the RRSIG covering the DS RR in the delegating parent. These validity periods should be short, which will require frequent re-signing.

To minimize the impact of a compromised ZSK, a zone administrator should set a rollover interval of no less than two months for the ZSK."
  desc 'check', 'Note: For Infoblox DNS systems on a Classified network, this requirement is Not Applicable.

Review the Infoblox DNSSEC configuration and validate the ZSK rollover interval is configured for a range of no more than two months.
Navigate to Data Management >> DNS >> Grid DNS properties. 

Toggle Advanced Mode and click on the "DNSSEC" tab. 

Validate the “Zone-Signing Key Rollover Interval” is configured to a value of less than two months.

If the “Zone-Signing Key Rollover Interval” is configured to a value more than two months, this is a finding.

When complete, click "Cancel" to exit the "Properties" screen.'
  desc 'fix', 'Navigate to Data Management >> DNS >> Grid DNS Properties. Toggle “Advanced Mode” and select the "DNSSEC" tab. 

Modify the “Zone-Signing Key Rollover Interval” to a period of less than two months. 

When complete, click "Save & Close" to save the changes and exit the "Properties" screen. 

Perform a service restart if necessary. 

Follow manual key rollover procedures and ensure changes are published to all applicable systems, including parent DNS systems.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15417r612204_chk'
  tag severity: 'medium'
  tag gid: 'V-214202'
  tag rid: 'SV-214202r612370_rule'
  tag stig_id: 'IDNS-7X-000710'
  tag gtitle: 'SRG-APP-000516-DNS-000078'
  tag fix_id: 'F-15415r612205_fix'
  tag 'documentable'
  tag legacy: ['V-68599', 'SV-83089']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
