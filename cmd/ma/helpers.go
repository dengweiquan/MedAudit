package main

import (
	"fmt"
	"net/url"
)

func escapePath(s string) string { return url.PathEscape(s) }

func fetchAssets(c *client) ([]assetRow, error) {
	var rows []assetRow
	if err := c.getJSON("/api/v1/assets", &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func findAsset(c *client, id string) (*assetRow, error) {
	rows, err := fetchAssets(c)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].ID == id {
			return &rows[i], nil
		}
	}
	return nil, fmt.Errorf("资产 %s 不存在", id)
}

func fetchBundles(c *client) ([]bundleSummary, error) {
	var rows []bundleSummary
	if err := c.getJSON("/api/v1/bundles", &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func findBundle(c *client, id string) (*bundleSummary, error) {
	rows, err := fetchBundles(c)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].ID == id {
			return &rows[i], nil
		}
	}
	return nil, fmt.Errorf("事实包 %s 不存在", id)
}
