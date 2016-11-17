Hack RUN Game Engine
====================

This is a Python hacking simulator game engine, it allows you to create games
which are similar to that of Hack RUN.  The game engine itself, comes with a
fully functional version of Hack RUN Free as an example game to demonstrate
how the engine works.

https://play.google.com/store/apps/details?id=com.i273.hackrunfree

The engine itself acts as a simple telnet server, and you play the game by
connecting to the server.  It is not multiplayer, however it may be possible
to implement such a system.  The server does keep track of sessions, which
makes it possible for all players to speak to one another.  The unused method
in the server class transmit() can be called by any of the clients to broadcast
a message to all players currently online.  An authentication system should be
pretty easy to set-up for this purpose as well.  Multiplayer may be considered
for future versions of this engine.

How to create your own content
------------------------------

The engine is very extendable, and it's very easy to add new features without
needing to code very much.  The example scenario displays how each variable
should be used, but this part of this document will also explain their
usage to extend the system.

**FILE_LISTS**:  This hash contains hosts along with a list of files those
hosts should contain when the player uses *ls*.  The corosponding text files
for each file should be stored under **gamedata/<hostname>/filename.txt**

**MAILBOXES**: This hash contains a list of usernames and their mailbox
messages.  You will need to create the needed text files in **gamedata*
for it to work properly.  See example files to get you started.

**FOLDERNAME**: This hash is used to display which folder a mail message
is located in.  It's a basic look-up table, and be updated with new
names.

**COMMAND_LISTS**: This hash is a look-up for which commands are available
on what systems the player can access.  "exit" and "help" are always
accessible.  Be sure these commands exist in your Python code.

**PROGRESS_TRIGGERS**: This hash contains game progression triggers, it is
based on what the player types at specific points in the game.  For example,
'type readme':[0,'localhost'] means that a trigger will occur if the player
types in "type readme" on "localhost", but only if the current progress is
at "0".  At the moment, the story must be linear.  This may change in future
versions of the engine.

**LOGIN_MAP**: This is a basic hash of usernames and their passwords used in
both the gateway and for workstation *jumps*.

**HR_MAP**: This hash just contains HR users which can sign into the HR Database.

**HR_DATABASE**: This hash is loaded in from a JSON source to populate the HR Database.

**HR_FIELDS**: This hash is used for the internal hradd method, which should not
be enabled on live games.

**REPS_MAP**: This hash is used to store the "Reps system" username and password.

**WEBSITES**: This list just stores the accessible websites to prevent direct
file system access until we know what the player entered is proper.

### gamedata directory

This directory contains mostly text files used within the game itself, and you
will want to modify them for your own specific game requirements.

**gamedata/greeting.txt**: This is the initial greeting displayed when a player
connects via telnet to introduce them to the game itself.

**gamedata/bootup.txt**: This is displayed right after the greeting and before
the prompt appears.  It shows a fake OS booting to get the player into the mood.

**gamedata/<system>/textfile.txt**: This is where FILE_LISTS files are stored.

**gamedata/mail/<system>/textfile.txt**: This is where mail for a specific system
is stored.  It's neither by username or hostname, but rather the internal system name.

**gamedata/web/website.com.txt**: This is displayed when the player visits a URL,
a better web browsing experience will be introduced in future versions.

### Special concepts and variables

Currently only **COMMAND_LISTS** and **MAILBOXES** are instance only, meaning that if
these are updated, only that player will see the updates.  All other main variables
above are completely global, so any updates to them, all players will see it!!!

**self.state**: This is a very special instance variable that contains what the server
should be doing with the next set of data to come in.  You can create new states by
creating a new Python method in **GameChannel** called *do_<state>(data)*.  The data
variable that comes into the method will contain what the client sent.

**self.sys**: This stores the current system the player is located in, and is used
to determine what's available to the player in terms of commands, files, and mail.

To create a new command for the **shell** state, just create a new method in **GameChannel**
called *cmd_<command>(arg)*, only include *arg* if the command is to take an
argument.  See example commands.

### Available states

The engine comes with a lot of premade states which you can switch to during gameplay.

**greeting**: This is the initial state when the player connects to the server.

**shell**: This is the most widely used state, it is a general command processor
and can be used for any system that takes basic command input.  It is used for
almost every system in the example game.

**gateway**: This state is used when the player runs the **gate** command, see
**cmd_gate** for how a state change to this state should operate.

**jump**: This state is used when the player runs the **jump** command, see
**cmd_jump** for how a state change to this state should operate.

**hr**: This state is used when logging into the HR Database, and accepts HR_MAP
username and passwords only.

**reps**: This state is used when logging into the Reps System.

**hrsearch**: This state is used when performing an HR Search, and was needed as it
differs from the general shell state.

### Available 'shell' commands

**ls**: This is used to list files in **FILE_LISTS**

**type**: This is used to display files in **gamedata/<system>/** which are in **FILE_LISTS**

**run**: This is used to start the so-called *hacker routine*.

**atip**: This is simply used to display a tip...

**note**: This is simply used to display a note...

**gate**: This is used to change the state over to 'gateway'.

**jump**: This is used to change the state over to 'jump'.

**mail**: This is used to change the system over to a user's mail.

**web**: This is used to display basic text files for websites.

**list**: This is used to display the contents of a **MAILBOX**.

**show**: This is used to display the contents of a mailbox message.

**hr**: This is used to change the state over to 'hr'.

**search**: This is used to change the state over to 'hrsearch'.

**reps**: This is used to change the state over to 'reps'.
