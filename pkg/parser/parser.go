package parser

import (
	"github.com/zaidkhan0997/POC-Recon/internal/parser"
	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

func NormalizeDomain(raw string) (string, error) {
	return parser.NormalizeDomain(raw)
}

func ParsePersonName(raw string) models.NameParts {
	return parser.ParsePersonName(raw)
}

func ExtractNameFromLinkedInSlug(slugOrURL string) *models.NameParts {
	return parser.ExtractNameFromLinkedInSlug(slugOrURL)
}
