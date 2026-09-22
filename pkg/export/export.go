package export

import (
	"github.com/zaidkhan0997/POC-Recon/internal/output"
	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

func ExportJSON(result *models.ReconResult, path string) error {
	return output.ExportJSON(result, path)
}

func ExportCSV(result *models.ReconResult, path string) error {
	return output.ExportCSV(result, path)
}

func ExportTXT(result *models.ReconResult, path string, showAll bool) error {
	return output.ExportTXT(result, path, showAll)
}

func ExportHTML(result *models.ReconResult, path string) error {
	return output.ExportHTML(result, path)
}

func OpenFolderInFileManager(dirPath string) error {
	return output.OpenFolderInFileManager(dirPath)
}
