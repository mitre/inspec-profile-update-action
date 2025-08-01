control 'SV-217786' do
  title 'Samsung Android must be configured to set the password history with a length of 0.'
  desc 'Password History Length controls the number of most recently used passwords stored in the Password History list. 

The Password History list does not store the actual value of the previous passwords but instead calculates the hash value of the passwords. When the user attempts to set a new password, the hash value of the password is first calculated and the Password History list is checked to determine if it already contains a matching value, rejecting the password if it does. If the password is accepted, the oldest entry in the Password History list is removed, and the newly calculated password hash is added to the list. 

The MDFPP requires that values derived from passwords are destroyed when no longer needed; therefore, the calculated hash values of previous passwords should not be stored in the Password History list. 

This feature must be configured for a Samsung Android device to be in the NIAP-certified Common Criteria (CC) mode of operation.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm that the password history is set to a length of "0". 

This procedure is performed on the MDM console only. 

On the MDM console, for the device, in the "Android password constraints" group, verify that "password history length" is set to "0". 

If on the MDM console "password history length" is not set to "0", this is a finding.'
  desc 'fix', 'Configure Samsung Android to set the password history with a length of "0". 

On the MDM console, for the device, in the "Android password constraints" group, set "password history length" to "0".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COPE KPE AE'
  tag check_id: 'C-19003r362651_chk'
  tag severity: 'medium'
  tag gid: 'V-217786'
  tag rid: 'SV-217786r388482_rule'
  tag stig_id: 'KNOX-09-001390'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-19001r362652_fix'
  tag 'documentable'
  tag legacy: ['SV-103921', 'V-93835']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
