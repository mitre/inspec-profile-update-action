control 'SV-104225' do
  title 'Symantec ProxySG must not have unnecessary services and functions enabled.'
  desc 'Information systems are capable of providing a wide variety of functions (capabilities or processes) and services. Some of these functions and services are installed and enabled by default. The organization must determine which functions and services are required to perform the content filtering and other necessary core functionality for each component of the ALG. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The primary function of an ALG is to provide application-specific content filtering and/or proxy services. The ALG application suite may integrate related content filtering and analysis services and tools (e.g., IPS, proxy, malware inspection, blacklists, whitelists). Some gateways may also include email scanning, decryption, caching, and DLP services. However, services and capabilities that are unrelated to this primary functionality must not be installed (e.g., DNS, email client or server, FTP server, or web server).

Next Generation ALGs (NGFW) and Unified Threat Management (UTM) ALGs integrate functions that have been traditionally separated. These products integrate content filtering features to provide more granular policy filtering. There may be operational drawbacks to combining these services into one device. Another issue is that NGFW and UTM products vary greatly with no current definitive industry standard.'
  desc 'check', 'Determine what proxy services are enabled on the ProxySG.

1. Log on to the Web Management Console
2. Browse to Configuration >> Services >> Proxy Services
3. Review each service specified in the list with the ProxySG administrator to verify that each is required.

If the Symantec ProxySG has any unnecessary services or functions enabled, this is a finding.'
  desc 'fix', 'Disable/remove unnecessary proxy services on the ProxySG. In particular, reverse proxy services should not configured if not used.

1. Log on to the Web Management Console
2. Browse to Configuration >> Services >> Proxy Services
3. Review each service and service group specified in the list with the ProxySG administrator.
4. Remove any unnecessary services or service groups by selecting them and clicking "Delete"
5. Click "Apply" once all unnecessary services or groups have been removed.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93457r2_chk'
  tag severity: 'medium'
  tag gid: 'V-94271'
  tag rid: 'SV-104225r1_rule'
  tag stig_id: 'SYMP-AG-000280'
  tag gtitle: 'SRG-NET-000131-ALG-000085'
  tag fix_id: 'F-100387r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
