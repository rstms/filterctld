package main

import (
	"github.com/stretchr/testify/require"
	"testing"
)

// path		    directory
// --------------   ------------------------------------
// INBOX	    /home/USER/Maildir/cur
// INBOX/folder	    /home/USER/Maildir/.INBOX.folder/cur
// INBOX/folder/sub /home/USER/Maildir/.INBOX.folder.sub/cur

func TestTransformPath(t *testing.T) {
	dir := transformPath("user", "/INBOX")
	require.Equal(t, dir, "/home/user/Maildir/cur")

	dir = transformPath("user", "/INBOX/spam")
	require.Equal(t, dir, "/home/user/Maildir/.INBOX.spam/cur")

	dir = transformPath("user", "/test")
	require.Equal(t, dir, "/home/user/Maildir/.test/cur")

	dir = transformPath("user", "/lists/lists-personal/Advertising")
	require.Equal(t, dir, "/home/user/Maildir/.lists.lists-personal.Advertising/cur")
}
