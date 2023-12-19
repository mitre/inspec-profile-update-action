control 'SV-223158' do
  title 'Firefox is not configured to prompt a user before downloading and opening required file types.'
  desc 'New file types cannot be added directly to the helper applications or plugins listing. Files with these extensions will not be allowed to use Firefox publicly available plugins and extensions to open.  The application will be configured to open these files using external applications only.  After a helper application or save to disk download action has been set, that action will be taken automatically for those types of files.  When the user receives a dialog box asking if you want to save the file or open it with a specified application, this indicates that a plugin does not exist. The user has not previously selected a download action or helper application to automatically use for that type of file. When prompted, if the user checks the option to Do this automatically for files like this from now on, then an entry will appear for that type of file in the plugins listing and this file type is automatically opened in the future. This can be a security issue.  New file types cannot be added directly to the Application plugin listing.'
  desc 'check', 'Open a browser window, type "about:config" in the address bar.
Criteria: If the “plugin.disable_full_page_plugin_for_types” value is not set to include the following external extensions and not locked, this is a finding:
PDF, FDF, XFDF, LSL, LSO, LSS, IQY, RQY, XLK, XLS, XLT, POT, PPS, PPT, DOS, DOT, WKS, BAT, PS, EPS, WCH, WCM, WB1, WB3, RTF, DOC, MDB, MDE, WBK, WB1, WCH, WCM, AD, ADP.'
  desc 'fix', 'Ensure the following extensions are not automatically opened by Firefox without user confirmation. Do not use plugins and add-ons to open these files.
Use the "plugin.disable_full_page_plugin_for_types" preference to set and lock the following extensions so that an external application, rather than an add-on or plugin, will not be used: 
PDF, FDF, XFDF, LSL, LSO, LSS, IQY, RQY, XLK, XLS, XLT, POT, PPS, PPT, DOS, DOT, WKS, BAT, PS, EPS, WCH, WCM, WB1, WB3, RTF, DOC, MDB, MDE, WBK, WB1, WCH, WCM, AD, ADP.'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24831r531291_chk'
  tag severity: 'medium'
  tag gid: 'V-223158'
  tag rid: 'SV-223158r612236_rule'
  tag stig_id: 'DTBF110'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-24819r531292_fix'
  tag 'documentable'
  tag legacy: ['SV-16711', 'V-15772']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
