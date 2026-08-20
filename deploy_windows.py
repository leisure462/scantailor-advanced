import os
import sys
import shutil
import struct

def get_imported_dlls(filepath):
    """Parse PE header and extract imported DLL names."""
    dlls = set()
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        
        if len(data) < 0x40 or data[:2] != b'MZ':
            return dlls
        
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        if e_lfanew + 4 > len(data) or data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
            return dlls
        
        magic = struct.unpack_from('<H', data, e_lfanew + 0x18)[0]
        if magic == 0x10B: # PE32
            import_rva_offset = e_lfanew + 0x18 + 96 + 8
            num_sections_offset = e_lfanew + 0x06
            opt_hdr_size_offset = e_lfanew + 0x14
        elif magic == 0x20B: # PE32+ (64-bit)
            import_rva_offset = e_lfanew + 0x18 + 112 + 8
            num_sections_offset = e_lfanew + 0x06
            opt_hdr_size_offset = e_lfanew + 0x14
        else:
            return dlls
        
        num_sections = struct.unpack_from('<H', data, num_sections_offset)[0]
        opt_hdr_size = struct.unpack_from('<H', data, opt_hdr_size_offset)[0]
        import_rva, import_size = struct.unpack_from('<II', data, import_rva_offset)
        
        if import_rva == 0 or import_size == 0:
            return dlls
        
        # Read section headers
        sect_table_offset = e_lfanew + 0x18 + opt_hdr_size
        sections = []
        for i in range(num_sections):
            hdr = data[sect_table_offset + i*40 : sect_table_offset + (i+1)*40]
            if len(hdr) < 40:
                break
            vsize, va, rsize, rptr = struct.unpack_from('<IIII', hdr, 8)
            sections.append((va, vsize, rptr, rsize))
        
        def rva_to_offset(rva):
            for va, vsize, rptr, rsize in sections:
                if va <= rva < va + max(vsize, rsize):
                    return rptr + (rva - va)
            return None
        
        import_offset = rva_to_offset(import_rva)
        if import_offset is None:
            return dlls
        
        # Parse import descriptors (each 20 bytes: ILT, TimeDate, Forwarder, NameRVA, IAT)
        curr = import_offset
        while curr + 20 <= len(data):
            ilt, timedate, fwd, name_rva, iat = struct.unpack_from('<IIIII', data, curr)
            if name_rva == 0:
                break
            name_offset = rva_to_offset(name_rva)
            if name_offset is not None and name_offset < len(data):
                null_pos = data.find(b'\x00', name_offset)
                if null_pos != -1:
                    dll_name = data[name_offset:null_pos].decode('utf-8', errors='ignore')
                    if dll_name:
                        dlls.add(dll_name.lower())
            curr += 20
            
    except Exception as e:
        print(f"Error parsing PE {filepath}: {e}")
    return dlls

def deploy(package_dir, ucrt_bin_dir):
    print(f"Deploying dependencies to {package_dir} from {ucrt_bin_dir}...")
    
    # Create qt.conf in package directory
    qt_conf_path = os.path.join(package_dir, 'qt.conf')
    with open(qt_conf_path, 'w', encoding='utf-8') as f:
        f.write("[Paths]\nPrefix = .\nPlugins = .\nTranslations = translations\n")
    print("Created qt.conf")

    # 1. Locate Qt plugins
    plugin_folders = ['platforms', 'styles', 'imageformats', 'iconengines', 'printsupport']
    qt_plugins_sources = [
        '/ucrt64/share/qt5/plugins',
        '/ucrt64/lib/qt5/plugins',
        '/ucrt64/plugins',
        'C:/msys64/ucrt64/share/qt5/plugins',
        'C:/msys64/ucrt64/lib/qt5/plugins',
        'C:/msys64/ucrt64/plugins'
    ]
    
    for src_base in qt_plugins_sources:
        if os.path.isdir(src_base):
            print(f"Found Qt plugins directory: {src_base}")
            for folder in plugin_folders:
                src_folder = os.path.join(src_base, folder)
                if os.path.isdir(src_folder):
                    # Copy to package_dir/<folder> and package_dir/plugins/<folder>
                    dst_folder1 = os.path.join(package_dir, folder)
                    dst_folder2 = os.path.join(package_dir, 'plugins', folder)
                    os.makedirs(dst_folder1, exist_ok=True)
                    os.makedirs(dst_folder2, exist_ok=True)
                    for f in os.listdir(src_folder):
                        if f.lower().endswith('.dll'):
                            src_file = os.path.join(src_folder, f)
                            shutil.copy2(src_file, os.path.join(dst_folder1, f))
                            shutil.copy2(src_file, os.path.join(dst_folder2, f))
                            print(f"Copied plugin: {folder}/{f}")

    # Build lookup of all DLLs available in ucrt_bin_dir
    available_dlls = {}
    if os.path.isdir(ucrt_bin_dir):
        for f in os.listdir(ucrt_bin_dir):
            if f.lower().endswith('.dll'):
                available_dlls[f.lower()] = os.path.join(ucrt_bin_dir, f)
    print(f"Found {len(available_dlls)} DLLs in {ucrt_bin_dir}")

    # Explicitly copy Qt5 and core dependencies
    prefixes = ['qt5', 'libboost', 'libjpeg', 'libpng', 'libtiff', 'zlib', 'libgcc', 'libstdc++', 'libwinpthread', 'libfreetype', 'libharfbuzz', 'libpcre', 'libglib', 'libintl', 'libiconv', 'libdouble-conversion', 'libbrotli', 'libgraphite', 'libzstd', 'libdeflate', 'liblzma']
    for dll_name, src_path in available_dlls.items():
        if any(dll_name.startswith(p) for p in prefixes):
            dst = os.path.join(package_dir, os.path.basename(src_path))
            if not os.path.exists(dst):
                shutil.copy2(src_path, dst)
                print(f"Copied runtime DLL: {os.path.basename(src_path)}")

    # 2. Iteratively discover all dependencies across all binaries and plugins
    processed = set()
    while True:
        all_binaries = []
        for root, _, files in os.walk(package_dir):
            for f in files:
                if f.lower().endswith(('.exe', '.dll')):
                    all_binaries.append(os.path.join(root, f))
        
        to_process = [b for b in all_binaries if b not in processed]
        if not to_process:
            break
        
        newly_copied = 0
        for b in to_process:
            processed.add(b)
            imported = get_imported_dlls(b)
            for imp in imported:
                if imp in available_dlls:
                    dst = os.path.join(package_dir, os.path.basename(available_dlls[imp]))
                    if not os.path.exists(dst):
                        shutil.copy2(available_dlls[imp], dst)
                        print(f"Auto-deployed dependency: {os.path.basename(available_dlls[imp])} (required by {os.path.basename(b)})")
                        newly_copied += 1
                        
        if newly_copied == 0:
            break

    print(f"Finished deployment. Total files in package: {len(os.listdir(package_dir))}")

if __name__ == '__main__':
    if len(sys.argv) > 2:
        deploy(sys.argv[1], sys.argv[2])
    else:
        pkg = sys.argv[1] if len(sys.argv) > 1 else 'package/scantailor-advanced-windows-x64'
        ucrt = '/ucrt64/bin' if os.path.exists('/ucrt64/bin') else 'C:/msys64/ucrt64/bin'
        deploy(pkg, ucrt)
