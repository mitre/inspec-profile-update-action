control 'SV-224256' do
  title 'CA 1 Tape Management system password will be changed from the default.'
  desc 'CA 1 Tape Management default system password is common with all CA 1 systems. With this password, CA 1 tape processing can be deactivated. This could allow for unauthorized access to information stored on tape volumes and the CA 1 Tape Management Catalog (TMC). The result may threaten the integrity and availability of the CA 1 Tape Management System, and compromise the confidentiality of customer data.'
  desc 'check', "Refer to the following report produced by the z/OS Data Collection:

- CA1RPT(TMSTMVT) - for r11.5 and below
- CA1RPT(TMOOPTxx) - for r12.0 and above

Automated Analysis
Refer to the following report produced by the z/OS Data Collection:

- PDI(ZCA10041)

For r11.5 and below refer to offset x'18' from the beginning of module TMSTMVT. For r12.0 and above refer to the SHUTDWN option specified in the TMOOPTxx. The TMOOPTxx member is specified in the TMOSYSxx member in the data set allocated by the TMSPARM DD statement in the TMSINIT STC. If the default CA 1 system password is not being utilized, this is not a finding.

NOTE: The default system password for CA 1 provided by CA is CA1(TMS). The default system passwords provided by SSO are SSOCA1DF and SSOC@1DF."
  desc 'fix', "The systems programmer/ISSO will ensure that the CA 1 system password is changed from the vendor default system password.

Verify upon installation that the password is not the same as the default password and user distributed with the original installation default.

For r11.5 and below refer to offset x'18' from the beginning of module TMSTMVT.

For r12.0 and above refer to the SHUTDWN option specified in the TMOOPTxx. The TMOOPTxx member is specified in the TMOSYSxx member in the data set allocated by the TMSPARM DD statement in the TMSINIT STC.

NOTE:	The default system password for CA 1 provided by CA is CA1(TMS). The default system passwords provided by SSO are SSOCA1DF and SSOC@1DF."
  impact 0.5
  ref 'DPMS Target zOS CA 1 Tape Management for ACF2'
  tag check_id: 'C-25929r868078_chk'
  tag severity: 'medium'
  tag gid: 'V-224256'
  tag rid: 'SV-224256r868080_rule'
  tag stig_id: 'ZCA10041'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-25917r868079_fix'
  tag 'documentable'
  tag legacy: ['SV-40107', 'V-22689']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
