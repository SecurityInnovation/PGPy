Messages
========

Other than plaintext, you may want to be able to form PGP Messages. These can be signed and then encrypted to one or
more recipients.

Creating New Messages
---------------------

New messages can be created quite easily::

    # this creates a standard message from text
    # it will also be compressed, by default with ZIP DEFLATE, unless otherwise specified
    text_message = pgpy.PGPMessage.new("This is a brand spankin' new message!")

    # if you'd like to pack a file into a message instead, you can do so
    # PGPMessage will store the basename of the file and the time it was last modified.
    file_message = pgpy.PGPMessage.new("path/to/a/file", file=True)

    # or, if you want to create a *cleartext* message, which is what you may know as a
    # canonicalized text document with an inline signature block, that is done by setting
    # cleartext=True. You can load the contents of a file as above, as well.
    ct_message = pgpy.PGPMessage.new("This is a shiny new cleartext document. Hooray!",
                                     cleartext=True)

Loading Existing Messages
-------------------------

Existing messages can also be loaded very simply. This is nearly identical to loading keys, except that
it only returns the new message object, instead of a tuple::

    # PGPMessage will automatically determine if this is a cleartext message or not
    message_from_file = pgpy.PGPMessage.from_file("path/to/a/message")
    message_from_blob = pgpy.PGPMessage.from_blob(msg_blob)

Exporting Messages
------------------

Messages can be exported in OpenPGP compliant binary or ASCII-armored formats.

In Python 3::

    # binary
    msgbytes = bytes(message)

    # ASCII armored
    # if message is cleartext, this will also properly canonicalize and dash-escape
    # the message text
    msgstr = str(message)

in Python 2::

    # binary
    msgbytes = message.__bytes__()

    # ASCII armored
    # if message is cleartext, this will also properly canonicalize and dash-escape
    # the message text
    msgstr = str(message)
