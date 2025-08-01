control 'SV-3512' do
  title 'NSA Type1 products and required procedures must be used to protect classified data at rest (DAR) on wireless devices used on a classified WLAN or WMAN.'
  desc 'NSA Type 1 products provide a high level of assurance that cryptography is implemented correctly and meets the standards for storage of classified information.  Use of cryptography that is not Type 1 certified violates policy and increases the risk that classified data will be compromised.'
  desc 'check', 'Detailed Policy requirements:

Type 1 products and required procedures must be used to protect classified data-at-rest on wireless computers that are used on a classified WLAN or WMAN. 

If NSA Type1 certified DAR encryption is not available, the following requirements apply:

- The storage media shall be physically removed from the computer and stored within a COMSEC-approved security container when the computer is not being used.
- The entire computer shall be placed within a COMSEC-approved security container, if the computer has embedded storage media that cannot be removed.

Check Procedures:

Interview the IAO to determine if devices with wireless functionality (e.g., laptops or PDAs with embedded radios) are used to store classified data.  If yes, verify the device is an NSA Type 1 certified product. 
Mark as a finding if a Type 1 product is not used, or if the storage media or device is not stored in a COMSEC-approved security container when not in use.'
  desc 'fix', 'Immediately discontinue use of the non-compliant device.'
  impact 0.7
  ref 'DPMS Target Harris Secnet 11'
  tag check_id: 'C-4027r1_chk'
  tag severity: 'high'
  tag gid: 'V-3512'
  tag rid: 'SV-3512r1_rule'
  tag stig_id: 'WIR0235'
  tag gtitle: 'Classified wireless Type 1 DAR encryption'
  tag fix_id: 'F-34121r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
