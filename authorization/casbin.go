package authorization

import (
	"encoding/csv"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/log"
	"github.com/pkg/errors"
	"log/slog"
	"strings"
)

// CasbinSlogLogger is a wrapper to use slog.Logger with Casbin.
type CasbinSlogLogger struct {
	logger  *slog.Logger
	enabled bool
}

func (l *CasbinSlogLogger) EnableLog(enable bool) {
	l.enabled = enable
}

func (l *CasbinSlogLogger) IsEnabled() bool {
	return l.enabled
}

func (l *CasbinSlogLogger) LogModel(model [][]string) {
	if !l.enabled {
		return
	}

	l.logger.Info("Model", slog.Any("model", model))
}

func (l *CasbinSlogLogger) LogEnforce(matcher string, request []interface{}, result bool, explains [][]string) {
	if !l.enabled {
		return
	}

	l.logger.Info("Enforce",
		slog.String("matcher", matcher),
		slog.Any("request", request),
		slog.Bool("result", result),
		slog.Any("explains", explains),
	)
}

func (l *CasbinSlogLogger) LogRole(roles []string) {
	if !l.enabled {
		return
	}

	l.logger.Info("Roles", slog.Any("roles", roles))
}

func (l *CasbinSlogLogger) LogPolicy(policy map[string][][]string) {
	if !l.enabled {
		return
	}

	l.logger.Info("Policy", slog.Any("policy", policy))
}

func (l *CasbinSlogLogger) LogError(err error, msg ...string) {
	if !l.enabled {
		return
	}

	l.logger.Error("Error", slog.Any("error", err), slog.Any("message", msg))
}

var _ log.Logger = (*CasbinSlogLogger)(nil)

// NewCasbinSlogLogger creates a new adapter for Casbin with slog.Logger.
func NewCasbinSlogLogger(logger *slog.Logger) *CasbinSlogLogger {
	return &CasbinSlogLogger{
		logger:  logger,
		enabled: false,
	}
}

func addPolicyFromString(enforcer *casbin.Enforcer, policyFileContent string) error {
	reader := csv.NewReader(strings.NewReader(policyFileContent))

	reader.FieldsPerRecord = -1

	records, err := reader.ReadAll()
	if err != nil {
		return errors.Wrap(err, "failed to read policy content")
	}

	for _, record := range records {
		if len(record) == 0 {
			continue
		}

		err = addPolicyFromRecord(enforcer, record)
		if err != nil {
			return errors.Wrap(err, "failed to add policy from record")
		}
	}

	return nil
}

func addPolicyFromRecord(enforcer *casbin.Enforcer, record []string) error {
	switch record[0] {
	case "p":
		err := addPolicyIfNotExists(enforcer, record[1:]...)
		if err != nil {
			return errors.Wrap(err, "failed to add policy if not exists")
		}

	case "g":
		err := addGroupingPolicyIfNotExists(enforcer, record[1:]...)
		if err != nil {
			return errors.Wrap(err, "failed to add grouping policy if not exists")
		}
	default:
		return errors.Errorf("unknown policy type: %s", record[0])
	}

	return nil
}

func addPolicyIfNotExists(enforcer *casbin.Enforcer, params ...string) error {
	args := make([]any, len(params))
	for i := range args {
		args[i] = params[i]
	}

	exists, err := enforcer.HasPolicy(args...)
	if err != nil {
		return errors.Wrap(err, "failed to check policy")
	}

	if exists {
		return nil
	}

	_, err = enforcer.AddPolicy(args...)
	if err != nil {
		return errors.Wrap(err, "failed to add policy")
	}

	return nil
}

func addGroupingPolicyIfNotExists(enforcer *casbin.Enforcer, params ...string) error {
	args := make([]any, len(params))
	for i := range args {
		args[i] = params[i]
	}

	exists, err := enforcer.HasGroupingPolicy(args...)
	if err != nil {
		return errors.Wrap(err, "failed to check policy")
	}

	if exists {
		return nil
	}

	_, err = enforcer.AddGroupingPolicy(args...)
	if err != nil {
		return errors.Wrap(err, "failed to add grouping policy")
	}

	return nil
}
