import multiprocessing
import os
import traceback
from androguard.misc import AnalyzeAPK
from androguard.core.apk import APK
from lxml import etree
import androguard.decompiler.decompile 

def serialize_manifest_xml(xml_element):
    """Convert lxml Element to a UTF-8 string."""
    try:
        return etree.tostring(xml_element, encoding="unicode", pretty_print=True)
    except Exception:
        return str(xml_element)




def extract_dex_strings(dex_objects):
    strings = set()
    try:
        for dex in dex_objects:
            for cls in dex.get_classes():
                for method in cls.get_methods():
                    code = method.get_code()
                    if code:
                        for insn in code.get_bc().get_instructions():
                            if insn.get_name() == "const-string":
                                s = insn.get_output().split('"', 1)[-1].rstrip('"')
                                if s and len(s) > 3:
                                    strings.add(s.strip())
    except Exception:
        pass
    return sorted(strings)


def analyze_apk_worker(apk_path, return_dict):
    try:
        a, d, dx = AnalyzeAPK(apk_path)
        return_dict['package_name'] = a.get_package()
        return_dict['version_name'] = a.get_androidversion_name()
        return_dict['version_code'] = a.get_androidversion_code()
        return_dict['manifest_xml'] = serialize_manifest_xml(a.get_android_manifest_xml())
        return_dict['permissions'] = a.get_permissions()
        
        # Real DEX string extraction
        return_dict['dex_strings'] = extract_dex_strings(d)
    except Exception as e:
        return_dict['error'] = f"{str(e)}\n{traceback.format_exc()}"


def decompile_apk(apk_path, timeout=20):
    """
    Performs deep analysis with a timeout and fallback for large/problematic files.
    Returns warning info when fallback occurs.
    """
    file_size_mb = os.path.getsize(apk_path) / (1024 * 1024)
    if file_size_mb > 10:
        info = basic_apk_info(apk_path)
        info['warning'] = "Used lightweight analysis due to APK size > 10MB."
        return info

    manager = multiprocessing.Manager()
    return_dict = manager.dict()
    p = multiprocessing.Process(target=analyze_apk_worker, args=(apk_path, return_dict))
    p.start()
    p.join(timeout)
    if p.is_alive():
        p.terminate()
        p.join()
        info = basic_apk_info(apk_path)
        info['warning'] = f"Full analysis timed out after {timeout}s; fallback to basic mode."
        return info

    results = dict(return_dict)
    if "error" in results:
        # Error in analysis, fallback
        info = basic_apk_info(apk_path)
        info['warning'] = f"Full analysis failed: {results['error']}. Fallback to basic mode."
        return info
    return results


def basic_apk_info(apk_path):
    try:
        a = APK(apk_path)
        return {
            "package_name": a.get_package(),
            "version_name": a.get_androidversion_name(),
            "version_code": a.get_androidversion_code(),
            "manifest_xml": serialize_manifest_xml(a.get_android_manifest_xml()),
            "permissions": a.get_permissions(),
            "dex_strings": [],
        }
    except Exception as e:
        return {"error": f"Failed lightweight analysis: {str(e)}\n{traceback.format_exc()}"}
