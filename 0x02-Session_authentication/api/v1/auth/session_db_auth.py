#!/usr/bin/env python3
""" SessionDBAuth class for managing sessions stored in the database. """

from api.v1.auth.session_exp_auth import SessionExpAuth
from models.user_session import UserSession


class SessionDBAuth(SessionExpAuth):
    """ Session authentication system storing session IDs in the database. """

    def create_session(self, user_id=None):
        """ Create and store a new session in the database. """
        session_id = super().create_session(user_id)
        if session_id is None:
            return None

        user_session = UserSession(user_id=user_id, session_id=session_id)
        user_session.save()
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """ Return the user ID associated with the session ID. """
        if session_id is None:
            return None

        sessions = UserSession.search({"session_id": session_id})
        if not sessions:
            return None

        return sessions[0].user_id

    def destroy_session(self, request=None):
        """ Destroy a session by removing it from the database. """
        session_id = self.session_cookie(request)
        if not session_id:
            return False

        sessions = UserSession.search({"session_id": session_id})
        if not sessions:
            return False

        for session in sessions:
            session.remove()

        return True
