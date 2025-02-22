control 'SV-48093' do
  title 'User training must include required topics.'
  desc 'Classified data could be exposed if users of client devices, that are components a campus WLAN system that is based on the CSfC Campus IEEE 802.11 Wireless Local Area Network (WLAN) Capability Package, are not aware of required operating procedures for safeguarding the client device and the data stored on the device.'
  desc 'check', 'Users should be trained on the following topics prior to being issued a client device that is a components a campus WLAN system that is based on the Campus WLAN Capability Package and annually thereafter.

-Client devices will not be connected to the network via wired connections.

-Client devices will be safeguarded as a piece of classified equipment. Required physical security controls, including classified marking labels, will be components of the training.

-Client device configuration will not be modified by the user.  Any exceptions that are required to operate the client device will be explained in user training.

Review site training records to verify required user training has been completed prior to users being issued a client device and at least annually. Review records for a sample of users (at least 3-4 records).

If required training has not been completed prior to users being issued a client device and at least annually, this is a finding.'
  desc 'fix', 'Have users complete required training.'
  impact 0.3
  ref 'DPMS Target CSfC Policy - WLAN CP'
  tag check_id: 'C-44832r2_chk'
  tag severity: 'low'
  tag gid: 'V-36592'
  tag rid: 'SV-48093r1_rule'
  tag stig_id: 'WIR-CWLAN-03'
  tag gtitle: 'User training for Campus WLAN system'
  tag fix_id: 'F-41231r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'PRTN-1'
end
