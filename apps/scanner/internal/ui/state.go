package ui

type State string

const (
	WaitingForKey     State = "WaitingForKey"
	Validating        State = "Validating"
	KeyValid          State = "KeyValid"
	KeyInvalid        State = "KeyInvalid"
	ServerUnavailable State = "ServerUnavailable"
	ConsentRequired   State = "ConsentRequired"
	Uploading         State = "Uploading"
	Completed         State = "Completed"
	Failed            State = "Failed"
)

func StatusMessage(state State) string {
	switch state {
	case Validating:
		return "Validating key..."
	case KeyValid:
		return "Key valid."
	case KeyInvalid:
		return "Invalid key."
	case ServerUnavailable:
		return "Server unavailable."
	case ConsentRequired:
		return "Review consent before starting scan."
	case Uploading:
		return "Uploading scan result..."
	case Completed:
		return "Scan uploaded successfully."
	case Failed:
		return "Scan failed."
	default:
		return "Waiting for scanner key."
	}
}
