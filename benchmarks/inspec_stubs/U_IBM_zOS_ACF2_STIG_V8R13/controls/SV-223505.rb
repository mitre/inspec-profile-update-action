control 'SV-223505' do
  title 'ACF2 must use NIST FIPS-validated cryptography to protect passwords in the security database.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

'
  desc 'check', 'From an ACF command screen enter:
SET CONTROL(GSO)
LIST PSWD

If the "GSO PSWD" record option "PSWDENCT" is set to "XDES" or null, this is a finding.

SET MSYSID(-)

LIST PSWD

For CA-ACF2 R16 and above:

If option "NOONEPWALG" is specified, and there is no transition plan with a definite completion date filed with the ISSM, this is a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option.

Develop a plan of action to implement the control option as specified below:

Configure the "GSO PSWD" record option "PSWDENCT" to "AES1".

For CA-ACF2 Release16 and above:

Configure "GSO PSWD" record option "PSWDENCT" to "AES1" or "AES2".

Configure the "GSO PSWD" to "ONEPWALG".

Note: If you are using VM Database Synchronization you cannot use "ONEPWALG". VM does not support the AES algorithms.

Develop a transition plan with a definite completion date for z/VM; file with the ISSM.

If all systems that are sharing the logonid or infostorage databases are not running with the same "PSWDENCT" value you cannot use "ONEPWALG".

Develop a transition plan that contains a definite completion date to migrate all logonid and infostorage databases to one "PSWDENCT" value; file with the ISSM.

Consult the CA-ACF2 administration guide for converting to "AES1" or "AES2" and using "ONEPWALG".'
  impact 0.7
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25178r695434_chk'
  tag severity: 'high'
  tag gid: 'V-223505'
  tag rid: 'SV-223505r877397_rule'
  tag stig_id: 'ACF2-ES-000880'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-25166r858861_fix'
  tag satisfies: ['SRG-OS-000073-GPOS-00041', 'SRG-OS-000074-GPOS-00042']
  tag 'documentable'
  tag legacy: ['SV-106817', 'V-97713']
  tag cci: ['CCI-000196', 'CCI-000197']
  tag nist: ['IA-5 (1) (c)', 'IA-5 (1) (c)']
end
