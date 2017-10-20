var W = WScript;
var F;
try {
	F = W.CreateObject('Scripting.FileSystemObject');
} catch(e) {
	W.Echo('FSO creation failed: ' + e.message);
	W.Quit(1);
}
var f;
try {
	f = F.GetFile(WScript.ScriptFullName);
} catch(e) {
	W.Echo('I don\'t exit: ' + e.message);
	W.Quit(1);
}

var dir_win32 = f.ParentFolder;
try {
	f = F.GetFolder(dir_win32);
} catch(e) {
	W.Echo('GetFolder failed: ' + e.message);
	W.Quit(1);
}
var dir_root = f.ParentFolder;
var file_versionsta = dir_root + '\\libquikav\\version.h.static';
var file_versionout = dir_root + '\\libquikav\\version.h';

W.Echo('Generating version.h');
if(F.FileExists(file_versionout))
	F.DeleteFile(file_versionout, true);

if(F.FileExists(file_versionsta)) {
	try {
		F.CopyFile(file_versionsta, file_versionout, true);
	} catch(e) {
		W.Echo('Cannot copy '+ file_versionsta +' to ' + file_versionout + ': ' + e.message);
		W.Quit(1);
	}
} else {
	var S;
	var version = '';
	try {
		S = W.CreateObject('WScript.Shell');
	} catch(e) {
		W.Echo('No Shell available: ' + e.message);
		W.Quit(1);
	}
	try {
		var git = S.Exec('git describe --always');
		version = git.StdOut.ReadAll();
		while(git.Status == 0) {
			W.Sleep(100);
		}
		if(git.ExitCode != 0) {
			W.Echo('WARNING: git describe returned ' + git.ExitCode);
			version = '';
		} else {
                        version = version.replace(/[\r\n]+$/, '');
                        if(version.match(/^quikav-([^-]+)$/))
				version = RegExp.$1;
                        else
				version = 'devel-' + version;
			version = '#define REPO_VERSION "' + version + '"';
		}
	} catch (e) {
		W.Echo('WARNING: Error executing git: ' + e.message);
	}
	of = F.CreateTextFile(file_versionout, true);
	if(!of) {
		W.Echo('Cannot open '+file_versionout+' for writing');
		W.Quit(1);
	}
	of.WriteLine('/* AUTOMATICALLY GENERATED BY configure.js */');
	if(version != '') 
		of.WriteLine(version);
	else
		W.Echo('WARNING: unable to determine repository revision');
	of.close();
}

W.Echo('Work complete');
W.Quit(0);

