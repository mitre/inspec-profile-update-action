control 'SV-9052' do
  title 'Anonymous Access to AD forest data above the rootDSE level must be disabled.'
  desc 'For Windows Server 2003 or above, the dsHeuristics option can be configured to override the default restriction on anonymous access to AD data above the rootDSE level. Anonymous access to AD data could provide valuable account or configuration information to an intruder trying to determine the most effective attack strategies.'
  desc 'check', '1. At the command line prompt enter (on a single line): 
dsquery * "cn=Directory Service,
cn=Windows NT,cn=Services,cn=Configuration,dc=[forest-name]" -scope base -attr * 

(Where dc=[forest-name] is the fully qualified LDAP name of the root of the domain being reviewed.)

Example:
The following is an example of the dsquery command for the vcfn.ost.com forest.

dsquery * "cn=Directory Service,cn=Windows  NT,cn=Services,cn=Configuration,  dc=vcfn,dc=ost,dc=com -scope base -attr * 

2. If the dsHeuristics attribute is listed, note the assigned value.

3. If the dsHeuristics attribute is defined and has a “2” as the 7th character, then this is a finding.

Examples of values that would be a finding as follows:
 “0000002”, “0010002”, “0000002000001”.
(The 7th character controls anonymous access.)

Supplementary Notes:
Domain controllers have this option disabled by default. However, this check verifies that the option has not been enabled.

The dsHeuristics option can be configured with the Windows Support Tools Active Directory Service Interfaces Editor (ADSI Edit) console (adsiedit.msc).'
  desc 'fix', 'Disable anonymous access to AD forest data above the rootDSE level.'
  impact 0.5
  ref 'DPMS Target Active Directory Forest'
  tag check_id: 'C-7713r1_chk'
  tag severity: 'medium'
  tag gid: 'V-8555'
  tag rid: 'SV-9052r2_rule'
  tag stig_id: 'AD.0230'
  tag gtitle: 'DS10.0230 dsHeuristics Option'
  tag fix_id: 'F-8074r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAN-1, ECCD-1, ECCD-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
