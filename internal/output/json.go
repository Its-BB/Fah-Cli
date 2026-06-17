package output

import (
	"encoding/json"
	"fmt"
	"io"
)

func JSON(w io.Writer, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

func ErrorJSON(w io.Writer, code string, message string) error {
	return JSON(w, map[string]string{"error": code, "message": message})
}
