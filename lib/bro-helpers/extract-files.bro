#
# Enable file carving in bro.
# Derived heavily from:
#   http://www.bro.org/sphinx-git/frameworks/file-analysis.html#adding-analysis
#
# Instructions:
#  1) Install this into your site/ config folder (where local.bro lives)
#
#  2) Add the following line to the bottom of local.bro
#       @load site/extract-files.bro
#
#  3) Run bro
#

global ext_map: table[string] of string = {
    ["application/x-dosexec"] = "exe",
    ["text/plain"] = "txt",
    ["image/jpeg"] = "jpg",
    ["image/png"] = "png",
    ["text/html"] = "html",
} &default ="";

# Define the folder you'd like files extracted into. The file names can be referenced
# against the files.log and the conn.log for the purposes of determining timestamp and
# connection-level information
redef FileExtract::prefix = "/var/tmp/bro-files/";

event file_new(f: fa_file)
{
    local ext = "";

    if ( f?$mime_type )
        ext = ext_map[f$mime_type];

    # This is the formatstring used to build the filename, you may change this to your liking
    local fname = fmt("%s-%s.%s", f$source, f$id, ext);
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
}
