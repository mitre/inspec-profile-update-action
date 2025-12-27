control 'SV-6994' do
  title 'Sensitive data stored on a USB device with persistent memory, that the data owner requires encryption is not encrypted using NIST-certified cryptography.'
  desc 'If the data owner believes that the data requires encryption it will be encrypted when at rest.  If it is not encrypted this can lead to the compromise of sensitive data.
The IAO, SA, and user will ensure that all sensitive data stored on a USB device with persistent memory, if required by the data owner, is encrypted using NIST-certified cryptography.'
  desc 'check', 'The reviewer will interview the IAO to verify that all sensitive data stored on a USB device with persistent memory, if required by the data owner, is encrypted using NIST-certified cryptography.'
  desc 'fix', 'Establish a process that will disseminate the requirement for encrypt of sensitive data that the data owner designates as needing encryption.  Also establish a process identifying which data needs to be encrypted and notifying the users that the identified data needs encryption.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2934r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6772'
  tag rid: 'SV-6994r1_rule'
  tag stig_id: 'USB01.007.00'
  tag gtitle: 'Unencrypted Sensitive Data'
  tag fix_id: 'F-6425r1_fix'
  tag 'documentable'
  tag potential_impacts: 'Encryption of data at rest can require excessive processor power; systems processor capabilities may need to be increased to meet response time requirements.'
  tag responsibility: ['Other', 'Information Assurance Officer', 'System Administrator']
end
